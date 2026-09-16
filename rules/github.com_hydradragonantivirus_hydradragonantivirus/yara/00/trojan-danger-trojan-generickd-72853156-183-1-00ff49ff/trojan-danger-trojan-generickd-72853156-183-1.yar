rule Trojan_Danger_Trojan_GenericKD_72853156_183_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_183_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "075f94f8404c55af52e67ec9ba9f3d076463c10fc70a939e48eea9af975c1fe6"

  strings:
    $s1  = "inosrrmgt headmv check" fullword ascii
    $s2  = "iread data" fullword ascii
    $s3  = "pugh spage jsr csne" fullword ascii
    $s4  = "wink na" fullword ascii
    $s5  = "pgram name " fullword ascii
    $s6  = "jxpmgtel heap e" fullword ascii
    $s7  = "jte dynamic fit lenkths trem" fullword ascii
    $s8  = "pugh spage jsr mrvi" fullword ascii
    $s9  = "pugh spage jsr avgu" fullword ascii
    $s10 = "inosrrmgt lata gheoo" fullword ascii
    $s11 = "ovmvsunwcrifed dynamic fit lenkths trem" fullword ascii
    $s12 = "pugh spage jsr " fullword ascii
    $s13 = "nze the GRT morm thar o" fullword ascii
    $s14 = "wight 1Y95-Q998 Mar" fullword ascii
    $s15 = ": the film hal al" fullword wide
    $s16 = "valid DatmTimm" fullword wide
    $s17 = "valid DatmTimmS" fullword wide
    $s18 = "g film" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}