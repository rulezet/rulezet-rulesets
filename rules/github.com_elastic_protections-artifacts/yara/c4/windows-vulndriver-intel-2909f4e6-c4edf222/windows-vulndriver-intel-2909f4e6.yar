rule Windows_VulnDriver_Intel_2909f4e6 {
    meta:
        author = "Elastic Security"
        id = "2909f4e6-7c69-4667-92f8-b64b746f83d5"
        fingerprint = "edca7fa9e3ea5f53558c19b3d6d276c3d40ce54e15ee47c706dd6cf90b6d2d55"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: SEMA Software"
        threat_name = "Windows.VulnDriver.Intel"
        reference_sample = "648994905b29b9c4a1074eef332bf6932b638bad62df020b5452c74e2b15d78f"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 45 4D 41 20 53 6F 66 74 77 61 72 65 }
        $str1 = "semav6msr64.pdb"
        $str2 = "IOCTL_SEMAV6MSR64_CLEAR_ONE"
        $str3 = "IOCTL_SEMAV6MSR64_WRITE_ONE"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2 and $str3
}