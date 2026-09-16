rule sig_20160315_ba95ba1aa402493f435a019507cb1986 {
  meta:
    description = "datamaliciousorder - file 20160315_ba95ba1aa402493f435a019507cb1986.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e053d67c6f3be7bd4c8d07d8aa9f10b90242f724399afa6c6cd05d94db36639c"

  strings:
    $s1 = "function zFZZGGiREGTgX(ulQxCCqnqtFB){WshShell[yPMgwQ + VEtwlsJav + BNqpBUM](ulQxCCqnqtFB, 0, 0);}" fullword ascii
    $s2 = "while (sTzueYbKYF.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s3 = "jy + EwAqOTUUmtbub + FipsuoHtk + avuuDbfljbnFbk + toLcUoshiMhRL, false);" fullword ascii
    $s4 = "function DaCePFpAREOj(n){return vdZNgSBzT + fnT1 + OFNOJkQE + ropoHx + qlLMgKSiSBnMEn + bWGYkJYwfTZh + eUAFIterLiQmM;}" fullword ascii
    $s5 = "sTzueYbKYF[SsApwryMgtKSJrl + ajZxksptxF](HSUHGvIgOrd + OuVDZjGs, dfSMSSh + xuDZngoUrzXC + xKDnyOvz + TMntc + eQgZtXtAsziC + uEXJ" ascii
    $s6 = "var XUolymZNodkGuu = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}