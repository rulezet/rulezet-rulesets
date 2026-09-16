rule __case_5295_1407 {
  meta:
    description = "5295 - file 1407.bin"
    author      = "The DFIR Report"
    reference   = "https://thedfirreport.com"
    date        = "2021-08-12"
    hash1       = "45910874dfe1a9c3c2306dd30ce922c46985f3b37a44cb14064a963e1244a726"

  strings:
    $s1 = "zG<<&Sa" fullword ascii
    $s2 = "r@TOAa" fullword ascii
    $s3 = "DTjt{R" fullword ascii

  condition:
    uint16(0) == 0xa880 and filesize < 2KB and
    all of them
}