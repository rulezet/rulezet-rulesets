rule INDICATOR_KB_ID_Ransomware_Ryuk {
    meta:
        author = "ditekShen"
        description = "Detects files referencing identities associated with Ryuk ransomware"
    strings:
        $s1 = "WayneEvenson@protonmail.com" ascii wide nocase
        $s2 = "WayneEvenson@tutanota.com" ascii wide nocase
        $s3 = "14hVKm7Ft2rxDBFTNkkRC3kGstMGp2A4hk" ascii wide
    condition:
        any of them
}