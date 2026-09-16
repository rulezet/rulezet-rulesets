rule Windows_VulnDriver_Insyde_311c2afc {
    meta:
        author = "Elastic Security"
        id = "311c2afc-ac2d-4353-9bb6-0a881e53bb16"
        fingerprint = "3dea9593b0e7e8a50effa34c527ae1594e81003a0f094c4718f16b06fb624371"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Insyde Software Corp., Version: <= 5.2.1.1"
        threat_name = "Windows.VulnDriver.Insyde"
        reference_sample = "ce0a4430d090ba2f1b46abeaae0cb5fd176ac39a236888fa363bf6f9fd6036d9"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 49 6E 73 79 64 65 20 53 6F 66 74 77 61 72 65 20 43 6F 72 70 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 69 00 73 00 63 00 66 00 6C 00 61 00 73 00 68 00 78 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x04][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x01][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x02-\x02][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00]|[\x02-\x02][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00]|[\x02-\x02][\x00-\x00][\x05-\x05][\x00-\x00][\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00])/
        $str1 = "iscflashx64.pdb"
        $str2 = "Insyde Flash Utility 64 bit Driver" wide
        $str3 = "iscflashx64.sys" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}