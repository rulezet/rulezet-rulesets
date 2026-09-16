rule ljncxcwmsg_7685 {
  meta:
    description = "Files - file ljncxcwmsg.gjf"
    author      = "The DFIR Report"
    reference   = "https://thedfirreport.com"
    date        = "2022-02-01"
    hash1       = "c789bb45cacf0de1720e707f9edd73b4ed0edc958b3ce2d8f0ad5d4a7596923a"

  strings:
    $s1  = "x=M:\"*" fullword ascii
    $s2  = "=DdlLxu" fullword ascii
    $s3  = "#+- 7 " fullword ascii
    $s4  = "1CTxH* " fullword ascii
    $s5  = "OF0+ K" fullword ascii
    $s6  = "\\oNvd4Ww" fullword ascii
    $s7  = "jvKSZ21" fullword ascii
    $s8  = "o%U%uhuc]" fullword ascii
    $s9  = "~rCcqlf1 0" fullword ascii
    $s10 = "kjoYf^=8" fullword ascii
    $s11 = "jpOMR4}" fullword ascii
    $s12 = "ZIIUn'u" fullword ascii
    $s13 = "7uCyy7=H" fullword ascii
    $s14 = "#c.sel}W" fullword ascii
    $s15 = ")t)uSKv%&}" fullword ascii
    $s16 = "VGiAP/o(" fullword ascii
    $s17 = "SwcF~i`" fullword ascii
    $s18 = "*ITDe5\\n" fullword ascii
    $s19 = "MjKB!X" fullword ascii
    $s20 = "tjfVUus" fullword ascii

  condition:
    uint16(0) == 0xa5a4 and filesize < 2000KB and
    8 of them
}