rule case_18543_pimpliest_kufic_png {
  meta:
    description = "18543 - file pimpliest_kufic.png"
    author      = "The DFIR Report via yarGen Rule Generator"
    reference   = "https://thedfirreport.com/2023/08/28/html-smuggling-leads-to-domain-wide-ransomware/"
    date        = "2023-08-28"
    hash1       = "c6294ebb7d2540ee7064c60d361afb54f637370287983c7e5e1e46115613169a"

  strings:
    $s1  = "rrr---" fullword ascii  
    $s2  = "RJjlJn93" fullword ascii
    $s3  = "CBnhJy+" fullword ascii
    $s4  = "nFSUFd#sn" fullword ascii
    $s5  = "ZIHV (N8" fullword ascii
    $s6  = "zzznnn+++fffggg" fullword ascii
    $s7  = "WWWYYY111SSS///" fullword ascii
    $s8  = "pBpl-{@hy#D" fullword ascii
    $s9  = "kv.NuQ<\\" fullword ascii
    $s10 = "wDWl{h5" fullword ascii
    $s11 = "3QWsTTog" fullword ascii
    $s12 = "djdr hX" fullword ascii
    $s13 = "MMMJJJ000GGGFFFRRR" fullword ascii
    $s14 = "AsYI^a/K" fullword ascii
    $s15 = "hWtw&cpk" fullword ascii
    $s16 = "QwoAMdi" fullword ascii
    $s17 = "CsIIzhS" fullword ascii
    $s18 = "yXqbrLb" fullword ascii
    $s19 = ")RQMWtuNZ}}" fullword ascii
    $s20 = "mupvqqxLj" fullword ascii

  condition:
    uint16(0) == 0x5089 and filesize < 400KB and
    8 of them
}