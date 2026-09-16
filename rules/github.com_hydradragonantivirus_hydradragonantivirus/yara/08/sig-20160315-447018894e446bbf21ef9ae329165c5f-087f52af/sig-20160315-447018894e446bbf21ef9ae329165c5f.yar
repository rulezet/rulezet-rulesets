rule sig_20160315_447018894e446bbf21ef9ae329165c5f {
  meta:
    description = "datamaliciousorder - file 20160315_447018894e446bbf21ef9ae329165c5f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "261cb3859b3b2fecba2d554bf2f9f440d9685dd58fdd5c3d1de367c52c44d0ea"

  strings:
    $s1 = "while (Cybf.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s2 = "function aDBk(oLpOINRXu){WshShell[cMTi](oLpOINRXu, 0, 0);}" fullword ascii
    $s3 = "var qHxUrtcZZYjUSMF = new Date();" fullword ascii
    $s4 = "Cybf[yRlqpQBaWuJ + mMHcaJayVyVqaON + bMkhmpAwXK](Xeb + jHVmJmIfmGX + gnRPoiUwFVTsCwA, oiZwrpb + pGmMJDMPdh + tXUGp + rjNcqiTvN +" ascii
    $s5 = "function uop(n){return WaRuO + WOERgne + yJdoHio + nKPHv + OPRlxU + hRE + tZqvGVs + FTYfoJCAyvK + qpTHPN + ENmQaXueFpG;}" fullword ascii
    $s6 = " OTvpgSEP, false);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}