rule Windows_VulnDriver_Zemana_a8ae6e90 {
    meta:
        author = "Elastic Security"
        id = "a8ae6e90-54f2-432a-bb2a-4e21ec11b9cf"
        fingerprint = "16ff200764264bc08ba392d714fa7a58bed2266facf432eef70688e98676cd26"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Zemana Ltd., Version: <= 1.8.2.320"
        threat_name = "Windows.VulnDriver.Zemana"
        reference_sample = "036c1151a30a9c25afc961d7305c58cbf8f68e5e5c1e726565c9a8168c2f3cdb"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 5A 65 6D 61 6E 61 20 4C 74 64 2E }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x07][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x08-\x08][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00]|[\x08-\x08][\x00-\x00][\x01-\x01][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\x3f][\x01-\x01])[\x02-\x02][\x00-\x00]|[\x08-\x08][\x00-\x00][\x01-\x01][\x00-\x00][\x40-\x40][\x01-\x01][\x02-\x02][\x00-\x00])/
        $str1 = "Win8KeyCrypt64.pdb"
        $str2 = "IOCTL_KEYCRYPT_DEACTIVATE_ENCRYPTION"
        $str3 = "IOCTL_KEYCRYPT_SYNC_INDEXES"
        $str4 = "AntiLogger Free" wide
        $str5 = "Zemana AntiLogger Free" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1 and $str2 and $str3 and $str4 and $str5
}