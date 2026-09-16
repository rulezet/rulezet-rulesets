rule Windows_VulnDriver_K7RKScan_70dced43 {
    meta:
        author = "Elastic Security"
        id = "70dced43-a2d7-4452-9d95-17a035c4fec0"
        fingerprint = "3c0c2fd1de9b32dd95d5d40352ad9d7e9ed4749a6182d32e185ea3cabbdce0ac"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Name: K7RKScan, Version: <= 15.1.0.6"
        threat_name = "Windows.VulnDriver.K7RKScan"
        reference_sample = "6004076ac3e43b0640e4d9e817c0a437e224a1c9813bbf61a9c47b7817cb2aa9"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 4B 00 37 00 52 00 4B 00 53 00 63 00 61 00 6E 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x0e][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x0f-\x0f][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x0f-\x0f][\x00-\x00][\x00-\x05][\x00-\x00][\x00-\x00][\x00-\x00]|[\x01-\x01][\x00-\x00][\x0f-\x0f][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "K7RKScan.pdb"
        $str2 = "K7RKScan" wide
        $str3 = "K7RKScan Kernel Module" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version and $str1 and $str2 and $str3
}