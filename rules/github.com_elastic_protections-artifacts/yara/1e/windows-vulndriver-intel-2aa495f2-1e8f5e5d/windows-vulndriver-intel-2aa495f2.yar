rule Windows_VulnDriver_Intel_2aa495f2 {
    meta:
        author = "Elastic Security"
        id = "2aa495f2-bd1e-4d47-bb75-619facb467e2"
        fingerprint = "856de428921d11b9400ee19600b929207b7b177f83893c77682a12b912890d14"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Intel(R) Software Products"
        threat_name = "Windows.VulnDriver.Intel"
        reference_sample = "11cf5a8c3a2cdd8df81e8c3e477bb84b25fb92becb41f35a5d675acaa1466890"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 49 6E 74 65 6C 28 52 29 20 53 6F 66 74 77 61 72 65 20 50 72 6F 64 75 63 74 73 }
        $str1 = "sepdrv3_1.pdb"
        $str2 = "IOCTL_GET_CHIPSET_DEVICE_ID"
        $str3 = "IOCTL_EM_CONFIG_NEXT_UNC"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2 and $str3
}