import "pe"
rule cobalt_strike_14435_dll_2 {
  meta:
    description = "32.dll"
    author      = "The DFIR Report"
    reference   = "https://thedfirreport.com/2022/09/12/dead-or-alive-an-emotet-story/"
    date        = "2022-09-12"
    hash1       = "76bfb4a73dc0d3f382d3877a83ce62b50828f713744659bb21c30569d368caf8"

  strings:
    $x1  = "mail glide drooping dismiss collation production mm refresh murderer start parade subscription accident retorted carter stalls r" ascii
    $s2  = "vlu405yd87.dll" fullword ascii
    $s3  = "XYVZSWWVU" fullword ascii  
    $s4  = "ZYWVWSXVT" fullword ascii  
    $s5  = "WXVZTVVUVX" fullword ascii  
    $s6  = "ZYXZXSWZW" fullword ascii  
    $s7  = "SZWVSZTVU" fullword ascii  
    $s8  = "VXVWUWVZYY" fullword ascii  
    $s9  = "VSXZZYSVU" fullword ascii  
    $s10 = "VXUZUVWVU" fullword ascii  
    $s11 = "SVVZZXZUVW" fullword ascii  
    $s12 = "USVZVSWVZ" fullword ascii  
    $s13 = "SWVVTVSVWWXZZVVV" fullword ascii  
    $s14 = "VSXVUXXZS" fullword ascii  
    $s15 = "WSVZYWZWWW" fullword ascii  
    $s16 = "XUSZXXVVW" fullword ascii  
    $s17 = "ZWZWZVZWWWZ" fullword ascii  
    $s18 = "STZVYVVZYS" fullword ascii  
    $s19 = "ZWZWYSZXUZ" fullword ascii  
    $s20 = "SVVWWVVVWW" fullword ascii  

  condition:
    uint16(0) == 0x5a4d and filesize < 2000KB and
    (pe.imphash() == "4e03b8b675969416fb0d10e8ab11f7c2" or (1 of ($x*) or 12 of them))
}