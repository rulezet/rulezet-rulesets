rule icedid_license_3930 {
  meta:
    description = "3930 - file license.dat"
    author      = "The DFIR Report"
    reference   = "https://thedfirreport.com"
    date        = "2021-06-09"
    hash1       = "29d2a8344bd725d7a8b43cc77a82b3db57a5226ce792ac4b37e7f73ec468510e"

  strings:
    $s1  = "iEQc- A1h" fullword ascii
    $s2  = "%n%DLj" fullword ascii
    $s3  = "n{Y@.hnPP#5\"~" fullword ascii
    $s4  = "(5N&#jUBE\"0" fullword ascii
    $s5  = "~JCyP+Av" fullword ascii
    $s6  = "iLVIy\\" fullword ascii
    $s7  = "RemwDVL" fullword ascii
    $s8  = "EQiH^,>A" fullword ascii
    $s9  = "#wmski;H" fullword ascii
    $s10 = "aHVAh}X" fullword ascii
    $s11 = "GEKK/no" fullword ascii
    $s12 = "focbZjQ" fullword ascii
    $s13 = "wHsJJX>e" fullword ascii
    $s14 = "cYRS:F#" fullword ascii
    $s15 = "EfNO\"h{" fullword ascii
    $s16 = "akCevJ]" fullword ascii
    $s17 = "8IMwwm}!" fullword ascii
    $s18 = "NrzMP?<>" fullword ascii
    $s19 = ".ZNrzLrU" fullword ascii
    $s20 = "sJlCJP[" fullword ascii

  condition:
    uint16(0) == 0x02ee and filesize < 1000KB and
    8 of them
}