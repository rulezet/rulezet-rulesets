rule Windows_VulnDriver_Lenovo_26b2c815 {
    meta:
        author = "Elastic Security"
        id = "26b2c815-f3cc-4e8a-b596-3cc4ef3c67f2"
        fingerprint = "0d524fb0bf5da518f8e4bdd8f7ba3c6540389aa2f1355ae114303075668a2e76"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Name: LnvMSRIO.sys, Version: <= 3.1.0.36"
        threat_name = "Windows.VulnDriver.Lenovo"
        reference_sample = "8936738fd34337ad70b1f4a38a0d45a4f1dac1091461b7a41e245b8322e32fc5"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 4C 00 6E 00 76 00 4D 00 53 00 52 00 49 00 4F 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\x23][\x00-\x00][\x00-\x00][\x00-\x00]|[\x01-\x01][\x00-\x00][\x03-\x03][\x00-\x00][\x24-\x24][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "LnvMSRIO.pdb"
        $str2 = "Lenovo filter driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version and $str1 and $str2
}