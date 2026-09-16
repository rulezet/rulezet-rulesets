rule icedid_032021_2 {
  meta:
    description = "1 - file license.dat"
    author      = "The DFIR Report"
    reference   = "https://thedfirreport.com"
    date        = "2021-03-21"
    hash1       = "45b6349ee9d53278f350b59d4a2a28890bbe9f9de6565453db4c085bb5875865"

  strings:
    $s1  = "+ M:{`n-" fullword ascii
    $s2  = "kwzzdd" fullword ascii
    $s3  = "w5O- >z" fullword ascii
    $s4  = "RRlK8n@~" fullword ascii
    $s5  = "aQXDUkBC" fullword ascii
    $s6  = "}i.ZSj*" fullword ascii
    $s7  = "kLeSM?" fullword ascii
    $s8  = "qmnIqD\")P" fullword ascii
    $s9  = "aFAeU!," fullword ascii
    $s10 = "Qjrf\"Q" fullword ascii
    $s11 = "PTpc,!P#" fullword ascii
    $s12 = "r@|JZOkfmT2" fullword ascii
    $s13 = "aPvBO,4" fullword ascii
    $s14 = ">fdFhl^S8Z" fullword ascii
    $s15 = "[syBE0\\" fullword ascii
    $s16 = "`YFOr.JH" fullword ascii
    $s17 = "C6ZVVF j7}" fullword ascii
    $s18 = "LPlagce" fullword ascii
    $s19 = "NLeF_-e`" fullword ascii
    $s20 = "HRRF|}O" fullword ascii

  condition:
    uint16(0) == 0x43da and filesize < 1000KB and
    8 of them
}