rule Windows_VulnDriver_Realtek_8302b517 {
    meta:
        author = "Elastic Security"
        id = "8302b517-704a-466e-a060-c9691751bb70"
        fingerprint = "bf1d06f7bd567df8e2554c2f06fa414eeb9f4dc38b57117b1d2abcfc5574d2d2"
        creation_date = "2026-05-22"
        last_modified = "2026-08-11"
        description = "Subject: Realtek Semiconductor Corp., Version: <= 1.8.823.2017"
        threat_name = "Windows.VulnDriver.Realtek"
        reference_sample = "082c39fe2e3217004206535e271ebd45c11eb072efde4cc9885b25ba5c39f91d"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 52 65 61 6C 74 65 6B 20 53 65 6D 69 63 6F 6E 64 75 63 74 6F 72 20 43 6F 72 70 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 72 00 74 00 6B 00 69 00 6F 00 77 00 38 00 78 00 36 00 34 00 2E 00 73 00 79 00 73 00 20 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x07][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x08-\x08][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x02]|[\x00-\x36][\x03-\x03])|[\x08-\x08][\x00-\x00][\x01-\x01][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x06]|[\x00-\xe0][\x07-\x07])[\x37-\x37][\x03-\x03]|[\x08-\x08][\x00-\x00][\x01-\x01][\x00-\x00][\xe1-\xe1][\x07-\x07][\x37-\x37][\x03-\x03])/
        $str1 = "rtkiow8x64.pdb"
        $str2 = "IOCTL_PHYMEM_INFORM_FP_FW_S3S4S5"
        $str3 = "IOCTL_PHYMEM_GETPCIULONG"
        $str4 = "Realtek IO Driver  " wide
        $str5 = "Realtek IO Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4 and $str5
}