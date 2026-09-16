rule Windows_VulnDriver_Intel_ae20e083 {
    meta:
        author = "Elastic Security"
        id = "ae20e083-4415-416a-a7e0-fcafbf9add0b"
        fingerprint = "884f38a382f90cb117e1f4383801e3295262acd773420879f975a2f2df778dee"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Intel(R) Software Products"
        threat_name = "Windows.VulnDriver.Intel"
        reference_sample = "54fc3cad3fc4d45eaf43b96b175a65879761c996c4e26880064170811b0a11ff"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 49 6E 74 65 6C 28 52 29 20 53 6F 66 74 77 61 72 65 20 50 72 6F 64 75 63 74 73 }
        $str1 = "sepdrv3_10.pdb"
        $str2 = "IOCTL_GET_CHIPSET_DEVICE_ID"
        $str3 = "IOCTL_WRITE_PCI_CONFIG"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2 and $str3
}