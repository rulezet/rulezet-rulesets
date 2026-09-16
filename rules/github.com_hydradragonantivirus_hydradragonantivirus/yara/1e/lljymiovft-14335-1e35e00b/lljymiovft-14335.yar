import "pe"
rule llJyMIOvft_14335 {
  meta:
    description = "llJyMIOvft.dll"
    author      = "The DFIR Report"
    reference   = "https://thedfirreport.com/2022/09/12/dead-or-alive-an-emotet-story/"
    date        = "2022-09-12"
    hash1       = "2b2e00ed89ce6898b9e58168488e72869f8e09f98fecb052143e15e98e5da9df"

  strings:
    $s1  = "Project1.dll" fullword ascii
    $s2  = "!>v:\"6;" fullword ascii
    $s3  = "y6./XoFz_6fw%r:6*" fullword ascii
    $s4  = "u3!RuF%OR_O*^$nw7&<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">" fullword ascii
    $s5  = "*/B+ n" fullword ascii
    $s6  = "ZnwFY66" fullword ascii
    $s7  = "1!f%G%w" fullword ascii
    $s8  = "QKMaXCL6" fullword ascii
    $s9  = "IMaRlh9" fullword ascii
    $s10 = "_BZRDe'7&7<<!{nBLU" fullword ascii
    $s11 = "lw7\"668!qZNL_EIS7IiMa" fullword ascii
    $s12 = "IS6\\JMtdHh0Piw2/PuH" fullword ascii
    $s13 = "iw#!RuF%OR__*^$nw76668!qZNL_EYS7I" fullword ascii
    $s14 = ".RuF%LR__*^$" fullword ascii
    $s15 = "^<_EHJ3IPLPeZX0Phg7!BAK%_" fullword ascii
    $s16 = "ilG8Rn\"2OIkY*E%zw'v669(pZGn_EH_6IE" fullword ascii
    $s17 = "ilg7Rnr0OI^]*JTnw6\"76<" fullword ascii
    $s18 = "Broken pipe" fullword ascii  
    $s19 = "Permission denied" fullword ascii  
    $s20 = "v)(Ro\">OHkU*D%xw9" fullword ascii

  condition:
    uint16(0) == 0x5a4d and filesize < 3000KB and
    (pe.imphash() == "066c972d2129d0e167d371a0abfcf03b" and (pe.exports("YAeJyEAYL7F4eDck6YUaf") and pe.exports("fmFkmnQYB5TC2Sq5NGFkK") and pe.exports("nrDjhnkd9nedaQwcCY")) or 12 of them)
}