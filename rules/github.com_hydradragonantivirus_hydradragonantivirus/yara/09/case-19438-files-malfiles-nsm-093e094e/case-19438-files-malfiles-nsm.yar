rule case_19438_files_MalFiles_NSM {
  meta:
    description = "19438 - file NSM.LIC"
    author      = "The DFIR Report"
    reference   = "https://thedfirreport.com/2023/10/30/netsupport-intrusion-results-in-domain-compromise"
    date        = "2023-10-29"
    hash1       = "dc6a52ad6d637eb407cc060e98dfeedcca1167e7f62688fb1c18580dd1d05747"

  strings:
    $s1  = "transport=0" fullword ascii
    $s2  = "[_License]" fullword ascii
    $s3  = "[[Enforce]]" fullword ascii
    $s4  = "licensee=XMLCTL" fullword ascii
    $s5  = "serial_no=NSM303008" fullword ascii
    $s6  = "control_only=0" fullword ascii
    $s7  = "inactive=0" fullword ascii
    $s8  = "maxslaves=9999" fullword ascii
    $s9  = "product=10" fullword ascii
    $s10 = "shrink_wrap=0" fullword ascii
    $s11 = "expiry=01/01/2028" fullword ascii

  condition:
    uint16(0) == 0x3231 and filesize < 1KB and
    8 of them
}