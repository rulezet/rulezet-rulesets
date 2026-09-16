rule SVG_Phishing_Brifutelectric_Temp_Location {
    strings:
        $name1 = "Remittance_Advice" ascii wide
        $name2 = "Remittance" ascii wide
        $name3 = "Advice" ascii wide
        $svg_ext = ".svg" ascii
    
    condition:
        ($name1 or ($name2 and $name3)) and $svg_ext and filesize < 5KB
}