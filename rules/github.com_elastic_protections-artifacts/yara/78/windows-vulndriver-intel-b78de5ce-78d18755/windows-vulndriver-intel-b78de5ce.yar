rule Windows_VulnDriver_Intel_b78de5ce {
    meta:
        author = "Elastic Security"
        id = "b78de5ce-5f19-4905-a4bf-7e581590cb5b"
        fingerprint = "0f3130f232b5db48f11ffeb4957a64a984a4f053d783ab1a1c4a358b1537938e"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Intel(R) Software Products"
        threat_name = "Windows.VulnDriver.Intel"
        reference_sample = "b96ba5c469591f9e545bef4af1719a831c73b71207fad79efd84335c1519f71a"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 49 6E 74 65 6C 28 52 29 20 53 6F 66 74 77 61 72 65 20 50 72 6F 64 75 63 74 73 }
        $str1 = "sepdrv3_15.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}