rule sig_20160315_45a332c9fc5c6be7fc98a6a878c4c7dd {
  meta:
    description = "datamaliciousorder - file 20160315_45a332c9fc5c6be7fc98a6a878c4c7dd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c51de8bb526a2f7028e4bdf28b80eeaf916ffc95aef0edb987675bf3cd6de45f"

  strings:
    $s1 = "function ZCWAQHPXlw(MGjjRvPglJpKQi){WshShell[rkbsluhSRVIdesT + mnivtkhulNHNk](MGjjRvPglJpKQi, 0, 0);}" fullword ascii
    $s2 = "while (NcdRse.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s3 = "NcdRse[LUTK + yOy](weeZgsKEfrodMxZ, jTMJYxzZKJdk + xdMbFK + BgXcxZjDTMIz + riCYCyRLiDQRkK + rBzKUcBz + LMuXULfJrIL + XCmhM + UlL" ascii
    $s4 = "function wgfmrrbxm(n){return YTUjbM + aMntyFD + VaEPLcE + saEDaHnLMXG + eUPsWjUQ + FjZBgHRHtW + SiEyFU + ZPeN;}" fullword ascii
    $s5 = " vXCTzUeGYTwWeM + eHDoQPXHSZeOE + gOpJu + wlipzafgsBfJBP, false);" fullword ascii
    $s6 = "var DCP = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}