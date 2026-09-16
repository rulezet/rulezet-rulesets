rule Windows_VulnDriver_Phoenix_ddac360a {
    meta:
        author = "Elastic Security"
        id = "ddac360a-bde6-4493-8d83-6e65adbec3d8"
        fingerprint = "a8c587561a85dd82da2367dee5a0b285398797d774adf309ac893abc630cd71f"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Phoenix Technology Ltd."
        threat_name = "Windows.VulnDriver.Phoenix"
        reference_sample = "316a27e2bdb86222bc7c8af4e5472166b02aec7f3f526901ce939094e5861f6d"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 50 68 6F 65 6E 69 78 20 54 65 63 68 6E 6F 6C 6F 67 79 20 4C 74 64 2E }
        $str1 = "WinFlash64.pdb"
        $str2 = "\\Device\\WinFlash"
        $str3 = "\\DosDevices\\WinFlash"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2 and $str3
}