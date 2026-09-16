rule Windows_VulnDriver_Ardrv_cfcc9510 {
    meta:
        author = "Elastic Security"
        id = "cfcc9510-5edd-4ab5-8722-7901feea22d4"
        fingerprint = "7aa2e5a43f6bda23cfa3ccdb7de19f95bdd5bc77ee8aeda9a1bc910a7456109a"
        creation_date = "2026-07-20"
        last_modified = "2026-08-11"
        description = "Subject: OPSWAT, Inc., Version: <= 2017.10.2.1551"
        threat_name = "Windows.VulnDriver.Ardrv"
        reference_sample = "07c5209bf83065fe760f4fee4ed2308b0c523671f68ca73a3854c2c8c28c0541"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4F 50 53 57 41 54 2C 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 61 00 72 00 64 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x06]|[\x00-\xe0][\x07-\x07])[\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x09][\x00-\x00][\xe1-\xe1][\x07-\x07][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x0a-\x0a][\x00-\x00][\xe1-\xe1][\x07-\x07][\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00]|[\x0a-\x0a][\x00-\x00][\xe1-\xe1][\x07-\x07]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x05]|[\x00-\x0e][\x06-\x06])[\x02-\x02][\x00-\x00]|[\x0a-\x0a][\x00-\x00][\xe1-\xe1][\x07-\x07][\x0f-\x0f][\x06-\x06][\x02-\x02][\x00-\x00])/
        $str1 = "ardrv.pdb"
        $str2 = "AppRemover Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}