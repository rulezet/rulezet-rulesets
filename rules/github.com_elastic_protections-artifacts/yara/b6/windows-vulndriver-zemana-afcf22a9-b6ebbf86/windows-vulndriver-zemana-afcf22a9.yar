rule Windows_VulnDriver_Zemana_afcf22a9 {
    meta:
        author = "Elastic Security"
        id = "afcf22a9-b01b-45fc-a5a1-3e93a80ec1a4"
        fingerprint = "3caa4081828ede7631630e3e9d55f5e96e01036a684cc3d631e1c63911e91c73"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Zemana Ltd., Version: <= 1.8.6.204"
        threat_name = "Windows.VulnDriver.Zemana"
        reference_sample = "2b34ca35bd4f61d8e1d62b6129bef0a64c4655e80d6d39da06cb27c08e6996a3"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 5A 65 6D 61 6E 61 20 4C 74 64 2E }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x07][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x08-\x08][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x05][\x00-\x00]|[\x08-\x08][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xcb][\x00-\x00][\x06-\x06][\x00-\x00]|[\x08-\x08][\x00-\x00][\x01-\x01][\x00-\x00][\xcc-\xcc][\x00-\x00][\x06-\x06][\x00-\x00])/
        $str1 = "KeyCrypt64.pdb"
        $str2 = "IOCTL_KEYCRYPT_DEACTIVATE_ENCRYPTION"
        $str3 = "IOCTL_KEYCRYPT_SYNC_INDEXES"
        $str4 = "AntiLogger SDK" wide
        $str5 = "Zemana AntiLogger SDK" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1 and $str2 and $str3 and $str4 and $str5
}