rule Windows_VulnDriver_IObit_4d2ac110 {
    meta:
        author = "Elastic Security"
        id = "4d2ac110-e4bc-4dcb-9ff6-74b7b5c70de0"
        fingerprint = "f2732b6db4806490669041f86b2fc9faea8cc3c0ae0dccb515567a1c4bce4023"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Name: IObitUnlocker.sys, Version: <= 1.3.0.15"
        threat_name = "Windows.VulnDriver.IObit"
        reference_sample = "1a77f9789dcb2365c38ac5ef860fecbd143dea5077da664fd56c99fd500822ca"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 49 00 4F 00 62 00 69 00 74 00 55 00 6E 00 6C 00 6F 00 63 00 6B 00 65 00 72 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x02][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x03-\x03][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x0e][\x00-\x00][\x00-\x00][\x00-\x00]|[\x03-\x03][\x00-\x00][\x01-\x01][\x00-\x00][\x0f-\x0f][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "IObitUnlocker.pdb"
        $str2 = "IObitUnlocker" wide
        $str3 = "File Unlock Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version and $str1 and $str2 and $str3
}