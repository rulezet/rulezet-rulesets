rule Windows_VulnDriver_Samsung_4c642da2 {
    meta:
        author = "Elastic Security"
        id = "4c642da2-171b-43cf-ae24-65e4e39a3d7b"
        fingerprint = "15652c23ca02de24ce3955dc9820405d032431436a9c498f49387d402a3479ed"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Samsung Electronics Co., Ltd."
        threat_name = "Windows.VulnDriver.Samsung"
        reference_sample = "be54f7279e69fb7651f98e91d24069dbc7c4c67e65850e486622ccbdc44d9a57"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 61 6D 73 75 6E 67 20 45 6C 65 63 74 72 6F 6E 69 63 73 20 43 6F 2E 2C 20 4C 74 64 2E }
        $str1 = "IOCTL_MAGICIAN_GET_AHCI_CONTROLLER_SATA_MODE"
        $str2 = "IOCTL_MAGICIAN_GET_AHCI_PORT_SATA_MODE"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2
}