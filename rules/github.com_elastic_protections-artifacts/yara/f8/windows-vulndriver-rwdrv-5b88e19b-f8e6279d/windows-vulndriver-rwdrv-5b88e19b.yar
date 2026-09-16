rule Windows_VulnDriver_RwDrv_5b88e19b {
    meta:
        author = "Elastic Security"
        id = "5b88e19b-340c-44ff-bc7a-d61ca993f29b"
        fingerprint = "e07c4f2b18145d788aecbae0beee802e274a9e8616d9cf6e9ebc1f0862b5e398"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: ccf(TestCo), Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.RwDrv"
        reference_sample = "3279593db91bb7ad5b489a01808c645eafafda6cc9c39f50d10ccc30203f2ddf"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 63 63 66 28 54 65 73 74 43 6F 29 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 52 00 77 00 44 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "RwDrv.pdb"
        $str2 = "RwDrv Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}