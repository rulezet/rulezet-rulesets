rule Windows_VulnDriver_JiangmenEyun_205aa263 {
    meta:
        author = "Elastic Security"
        id = "205aa263-ac5a-48f0-8b1d-5ce10ebae3f9"
        fingerprint = "125e6b4691cab29a5564927d404c63fc40b2b3d42869ae086daad7b082075240"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Jiangmen Eyun Network Co., Ltd., Version: <= 1.2.0.0"
        threat_name = "Windows.VulnDriver.JiangmenEyun"
        reference_sample = "c35cab244bd88bf0b1e7fc89c587d82763f66cf1108084713f867f72cc6f3633"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4A 69 61 6E 67 6D 65 6E 20 45 79 75 6E 20 4E 65 74 77 6F 72 6B 20 43 6F 2E 2C 20 4C 74 64 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 44 00 63 00 50 00 72 00 6F 00 74 00 65 00 63 00 74 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x02-\x02][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "DcProtect.pdb"
        $str2 = "DcProtect (R) Win8x86 driver " wide
        $str3 = "DcProtect Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}