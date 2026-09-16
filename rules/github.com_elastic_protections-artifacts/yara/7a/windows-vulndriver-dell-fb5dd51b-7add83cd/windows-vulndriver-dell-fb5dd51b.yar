rule Windows_VulnDriver_Dell_fb5dd51b {
    meta:
        author = "Elastic Security"
        id = "fb5dd51b-1161-434f-9bb6-3ee50ffd8379"
        fingerprint = "62e695d1be0822241318c2ea5adca4d5e0bd6ef29d3dd5c603388fc2230bb7f5"
        creation_date = "2026-07-22"
        last_modified = "2026-08-11"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher, Version: <= 2.0.3.0"
        threat_name = "Windows.VulnDriver.Dell"
        reference_sample = "1f46f7a8f414bb1ac9f875799efa4b5f62bd18806c64b17d961007755accb5ab"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 64 00 64 00 64 00 72 00 69 00 76 00 65 00 72 00 36 00 34 00 44 00 63 00 73 00 61 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00][\x03-\x03][\x00-\x00])/
        $str1 = "dddriver64Dcsa.pdb"
        $str2 = "IOCTL_DIAG_READ_LAST_PWRSTATE"
        $str3 = "IOCTL_DIAG_WRITE_MSR"
        $str4 = "Dell Diags Universal Device Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4
}