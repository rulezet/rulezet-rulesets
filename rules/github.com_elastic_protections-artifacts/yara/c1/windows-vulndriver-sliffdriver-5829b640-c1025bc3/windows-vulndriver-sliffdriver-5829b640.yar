rule Windows_VulnDriver_SliffDriver_5829b640 {
    meta:
        author = "Elastic Security"
        id = "5829b640-6846-422d-a1e8-f8f1e913acc6"
        fingerprint = "1c8442132f8a06e06e0d5880f84e77f1ad8af65dc6d79f6cdf8d1899b3ad7a91"
        creation_date = "2026-07-21"
        last_modified = "2026-08-11"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher"
        threat_name = "Windows.VulnDriver.SliffDriver"
        reference_sample = "b811da59fbd212eb2c3bc0ed92e8ea2e46ef4df40c2d0991d911e72008bfc1fa"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $str1 = "C:\\Users\\rmvr\\source\\repos\\MyDriver1\\x64\\Release\\SliffDriver.pdb"
        $str2 = "SLIFF_VD_IOCTL_GET_PCI_BAR"
        $str3 = "SliffDriver Unloaded"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2 and $str3
}