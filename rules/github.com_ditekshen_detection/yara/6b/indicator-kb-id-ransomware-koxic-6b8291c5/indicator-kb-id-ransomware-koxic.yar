rule INDICATOR_KB_ID_Ransomware_Koxic {
    meta:
        author = "ditekShen"
        description = "Detects files referencing identities associated with LokiLocker ransomware"
    strings:
        $s1 = "wilhelmkox@tutanota.com" ascii wide nocase
        $s2 = "F3C777D22A0686055A3558917315676D607026B680DA5C8D3D4D887017A2A844F546AE59F59F" ascii wide
    condition:
        any of them
}