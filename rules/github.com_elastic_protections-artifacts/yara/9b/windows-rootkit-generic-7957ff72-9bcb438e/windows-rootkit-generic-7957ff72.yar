rule Windows_Rootkit_Generic_7957ff72 {
    meta:
        author = "Elastic Security"
        id = "7957ff72-2aa8-4327-90c0-5674a0dcd5bc"
        fingerprint = "ff6131469e2be71d9a88e05584a6c51432836beaa2fbdb080b94bf2c4d426917"
        creation_date = "2026-07-21"
        last_modified = "2026-08-11"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher"
        threat_name = "Windows.Rootkit.Generic"
        reference_sample = "42bbad0caff790db44833fc67a202850576d73d278ea85fb8095e3f93b0b4370"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $str1 = "D:\\Projects\\StolenDriver\\KMDF\\bin\\Release\\watabe.pdb"
        $str2 = "\\DosDevices\\safezone04" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2
}