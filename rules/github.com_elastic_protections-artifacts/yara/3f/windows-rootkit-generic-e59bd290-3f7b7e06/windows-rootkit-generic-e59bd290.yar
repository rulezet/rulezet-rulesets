rule Windows_Rootkit_Generic_e59bd290 {
    meta:
        author = "Elastic Security"
        id = "e59bd290-2bda-4bfc-a1ff-67c612185f24"
        fingerprint = "30d22ceba3031dea1af6118920ecfbd3c286422bb612014b03063237d0478f50"
        creation_date = "2026-07-22"
        last_modified = "2026-08-11"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher"
        threat_name = "Windows.Rootkit.Generic"
        reference_sample = "d6d219628ab3acdc799b1b631d378742a4b266d6f55b12e568e4054091b08be6"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $str1 = "C:\\Users\\Blluettw -_-\\Downloads\\ioctl-main\\kprlRW\\x64\\Release\\kprl.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}