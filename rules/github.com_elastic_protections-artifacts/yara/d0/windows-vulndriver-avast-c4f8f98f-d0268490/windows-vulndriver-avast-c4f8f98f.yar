rule Windows_VulnDriver_Avast_c4f8f98f {
    meta:
        author = "Elastic Security"
        id = "c4f8f98f-36d0-404c-b740-f817b6e0eb7a"
        fingerprint = "0f79ad41d649478b0d7ae3762d07b01ada1d3ff2e473f5b6dd973432897b6a9f"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: AVAST Software a.s., Version: <= 10.0.0.1126"
        threat_name = "Windows.VulnDriver.Avast"
        reference_sample = "e8eb1c821dbf56bde05c0c49f6d560021628df89c29192058ce68907e7048994"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 56 41 53 54 20 53 6F 66 74 77 61 72 65 20 61 2E 73 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6E 00 67 00 69 00 6F 00 64 00 72 00 69 00 76 00 65 00 72 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x09][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x0a-\x0a][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x03]|[\x00-\x65][\x04-\x04])[\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x0a-\x0a][\x00-\x00][\x66-\x66][\x04-\x04][\x00-\x00][\x00-\x00])/
        $str1 = "ngiodriver_x64.pdb"
        $str2 = "avast! NG" wide
        $str3 = "avast! NG setup helper driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}