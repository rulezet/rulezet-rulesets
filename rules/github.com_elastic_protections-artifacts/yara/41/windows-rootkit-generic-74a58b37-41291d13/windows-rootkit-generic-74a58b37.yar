rule Windows_Rootkit_Generic_74a58b37 {
    meta:
        author = "Elastic Security"
        id = "74a58b37-0f09-48a3-9cff-91f8fdccd20d"
        fingerprint = "418e128b26ed6021c757e9eac380a684d6a9908a7f3b74c2983028e9348e9fba"
        creation_date = "2026-07-26"
        last_modified = "2026-08-11"
        description = "Subject: 中兴通讯股份有限公司"
        threat_name = "Windows.Rootkit.Generic"
        reference_sample = "1c763af41b74c7502d70093763723939a8025199e0ac7e39c04b5cf992f9e273"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] E4 B8 AD E5 85 B4 E9 80 9A E8 AE AF E8 82 A1 E4 BB BD E6 9C 89 E9 99 90 E5 85 AC E5 8F B8 }
        $str1 = "rwdriver.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}