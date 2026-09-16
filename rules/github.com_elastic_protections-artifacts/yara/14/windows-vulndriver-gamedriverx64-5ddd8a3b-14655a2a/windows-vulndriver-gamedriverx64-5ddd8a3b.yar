rule Windows_VulnDriver_GameDriverX64_5ddd8a3b {
    meta:
        author = "Elastic Security"
        id = "5ddd8a3b-cecf-471f-bd0e-1f71a5b43526"
        fingerprint = "3434c3beffd106185ac45045cae3c18e6a6dd34b1117558a4d7a9b01cabad4df"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Fedeen Games Limited, Version: <= 7.23.4.7"
        threat_name = "Windows.VulnDriver.GameDriverX64"
        reference_sample = "794bb1fc1b9b86d41d2a296511124a95fe0c43b59c977c702e4f5b368b0f7d4b"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 46 65 64 65 65 6E 20 47 61 6D 65 73 20 4C 69 6D 69 74 65 64 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 47 00 61 00 6D 00 65 00 44 00 72 00 69 00 76 00 65 00 72 00 58 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x16][\x00-\x00][\x07-\x07][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x17-\x17][\x00-\x00][\x07-\x07][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x03][\x00-\x00]|[\x17-\x17][\x00-\x00][\x07-\x07][\x00-\x00][\x00-\x06][\x00-\x00][\x04-\x04][\x00-\x00]|[\x17-\x17][\x00-\x00][\x07-\x07][\x00-\x00][\x07-\x07][\x00-\x00][\x04-\x04][\x00-\x00])/
        $str1 = "PwrdDriver.pdb"
        $str2 = "GameDriverX64" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}