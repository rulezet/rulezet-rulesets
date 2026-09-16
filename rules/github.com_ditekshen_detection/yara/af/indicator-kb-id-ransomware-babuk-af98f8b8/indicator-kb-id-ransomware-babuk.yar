rule INDICATOR_KB_ID_Ransomware_Babuk {
    meta:
        author = "ditekShen"
        description = "Detects files referencing identities associated with Babuk ransomware"
    strings:
        $s1 = "mitnickd@ctemplar.com" ascii wide nocase
        $s2 = "zar8b@tuta.io" ascii wide nocase
        $s3 = "recover300dollars@gmail.com" ascii wide nocase
        $s4 = "support.3330@gmail.com" ascii wide nocase
        $s5 = "decryptdelta@gmail.com" ascii wide nocase
        $s6 = "pyotrmaksim@gmail.com" ascii wide nocase
        $s7 = "retrievedata300@gmail.com" ascii wide nocase
        $s8 = "3JG36KY6abZTnHBdQCon1hheC3Wa2bdyqs" ascii wide         $s9 = "46zdZVRjm9XJhdjpipwtYDY51NKbD74bfEffxmbqPjwH6efTYrtvbU5Et4AKCre9MeiqtiR51Lvg2X8dXv1tP7nxLaEHKKQ" ascii wide     condition:
        any of them
}