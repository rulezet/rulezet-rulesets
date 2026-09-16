rule detect_Auto_Color {
    meta:
        description = "Detects Auto-color malware family "
        author = "Mohamed Ezzat (@ZW01f)"
        hash1  = "815b74947d3a78a1b7d2aece43596ddc0ffc264e26092f1f9b6409c62e1437d6"
        hash2  = "270fc72074c697ba5921f7b61a6128b968ca6ccbf8906645e796cfc3072d4c43"

    strings:
        $elf = "\x7fELF"         $s1 = "/var/log/cross"  
        $s2 = "/tmp/cross"   
        $s3 = "/door-%d.log"  
        $s4 = "/etc/ld.so.preload.xxx" 
        $s5 = "%s/auto-color" ascii wide 
        $s6 = "%s memory dump %d bytes..." wide ascii

    condition:
        (filesize < 300KB) and ($elf at 0) and (5 of ($s*)) 
}