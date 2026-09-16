rule Windows_VulnDriver_Nvidia_36de2baa {
    meta:
        author = "Elastic Security"
        id = "36de2baa-1e66-4776-b8c9-bbbfbc7f9d4c"
        fingerprint = "15a59b68e00d299041ba33348c191f742788199cf95209288e4860d4e4822811"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: NVIDIA Corporation"
        threat_name = "Windows.VulnDriver.Nvidia"
        reference_sample = "159dcf37dc723d6db2bad46ed6a1b0e31d72390ec298a5413c7be318aef4a241"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4E 56 49 44 49 41 20 43 6F 72 70 6F 72 61 74 69 6F 6E }
        $str1 = "nvflash.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $str1
}