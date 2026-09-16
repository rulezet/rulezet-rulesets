rule sig_20161129_003f2f8deb4a5834398e51bbdc8dd247 {
  meta:
    description = "datamaliciousorder - file 20161129_003f2f8deb4a5834398e51bbdc8dd247.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1e10ef889bd7905f7cccc1f853d562fa8591eb74cf897fcbdf785aa995e8d4cc"

  strings:
    $s1  = "var kcysda = new Array(-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -" ascii
    $s2  = "var kcysda = new Array(-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -" ascii
    $s3  = "var uquxw = new Array(-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, \"re\", -1, -1, -1, -1" ascii
    $s4  = "var lijaxd = new Array(-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, \"1]\", -1, -1, -1, -1, -1, -1, -1, -1, -" ascii
    $s5  = "var byjtohp1 = new Function([\"ret\", '$', '$', '$', '$', '$', '$', '$', '$', '$', '$', '$', '$', '$', '$'].exbojyqq() + [\"urn" ascii
    $s6  = "var gfakonfy = new Array(-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, \"va\", -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1," ascii
    $s7  = "var uquxw = new Array(-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, \"re\", -1, -1, -1, -1" ascii
    $s8  = "var lijaxd = new Array(-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, \"1]\", -1, -1, -1, -1, -1, -1, -1, -1, -" ascii
    $s9  = "if (typeof window == 'undefined') Array[yxkas][\"exbojyqq\"] = new Array(-1, new Function(luvy), -1, -1, -1, -1, -1, -1, -1, -1," ascii
    $s10 = "var gesrig = new Array(-1, -1, -1, \";\", -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1" ascii
    $s11 = "var gesrig = new Array(-1, -1, -1, \";\", -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1" ascii
    $s12 = "var wywhy = new Array(-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1" ascii
    $s13 = "if (typeof window == 'undefined') Array[yxkas][\"exbojyqq\"] = new Array(-1, new Function(luvy), -1, -1, -1, -1, -1, -1, -1, -1," ascii
    $s14 = "var gfakonfy = new Array(-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, \"va\", -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1," ascii
    $s15 = "var byjtohp1 = new Function([\"ret\", '$', '$', '$', '$', '$', '$', '$', '$', '$', '$', '$', '$', '$', '$'].exbojyqq() + [\"urn" ascii
    $s16 = "var wywhy = new Array(-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1" ascii
    $s17 = "switch (edyconykp9[[xvidy][0]] > 4) {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}