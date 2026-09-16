rule INDICATOR_KB_ID_Ransomware_Xorist {
    meta:
        author = "ditekShen"
        description = "Detects files referencing identities associated with Xorist ransomware"
    strings:
        $s1 = "@root_backdoor_synaptics_V" ascii wide nocase
        $s2 = "@DosX_Plus" ascii wide nocase
        $s3 = "@Cinoshi_Adm" ascii wide nocase
        $s4 = "@ac3ss0r" ascii wide nocase
        $s5 = "MCwRK1Z7K4GYHt9ZrbTR2SMCEqzqQaTbRF" ascii wide
        $s6 = "0x334F093c9De6552AF4cC0B252dA82aC77FeB467D" ascii wide
    condition:
        any of them
}