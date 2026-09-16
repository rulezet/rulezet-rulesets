import "pe"
rule CS_DLL {
  meta:
    description = "62.dll"
    author      = "The DFIR Report"
    reference   = "https://thedfirreport.com"
    date        = "2021-07-07"
    hash1       = "8b9d605b826258e07e63687d1cefb078008e1a9c48c34bc131d7781b142c84ab"

  strings:
    $s1 = "Common causes completion include incomplete download and damaged media" fullword ascii
    $s2 = "StartW" fullword ascii
    $s4 = ".rdata$zzzdbg" fullword ascii

  condition:
    uint16(0) == 0x5a4d and filesize < 70KB and (pe.imphash() == "42205b145650671fa4469a6321ccf8bf")
    or (all of them)
}