rule Windows_VulnDriver_Realtek_9316b8f8 {
    meta:
        author = "Elastic Security"
        id = "9316b8f8-b25a-4f37-9d2b-3121adab493b"
        fingerprint = "38665053063bee0beed1e8977b04d24670eb94fdf671cf84122b5b144eb0c00e"
        creation_date = "2026-05-22"
        last_modified = "2026-08-11"
        description = "Subject: Realtek Semiconductor Corp"
        threat_name = "Windows.VulnDriver.Realtek"
        reference_sample = "461c2a34dded78988addb0a5e8b7055ae4919f8bf2373056dcce5d03b76dd49d"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 52 65 61 6C 74 65 6B 20 53 65 6D 69 63 6F 6E 64 75 63 74 6F 72 20 43 6F 72 70 }
        $str1 = "LPTIO.pdb"
        $str2 = "IOCTL_WINIO_UNMAPPHYSADDR"
        $str3 = "IOCTL_WINIO_MAPPHYSTOLIN"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2 and $str3
}