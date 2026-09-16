rule INDICATOR_JAVA_Packed_Allatori {
    meta:
        author = "ditekSHen"
        description = "Detects files packed with Allatori Java Obfuscator"
    strings:
        $s1 = "# Obfuscation by Allatori Obfuscator" ascii wide
    condition:
        all of them
}