rule sig_20160316_9431d8c49107a163c03974b185010e70 {
  meta:
    description = "datamaliciousorder - file 20160316_9431d8c49107a163c03974b185010e70.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b6fc84e86fa20a164e65acbb19ba50f8a944f3663997fc75949d63a724902212"

  strings:
    $s1 = "while (XASjZRV[qisISjbPIGl + aVbuavzemg + xZdq + VvxwUpUaaO + fUlrA + qakwxB + TyHKbkqkz] < 4 ) {WScript[hwywujowKIEkW + tTcXagn" ascii
    $s2 = "while (XASjZRV[qisISjbPIGl + aVbuavzemg + xZdq + VvxwUpUaaO + fUlrA + qakwxB + TyHKbkqkz] < 4 ) {WScript[hwywujowKIEkW + tTcXagn" ascii
    $s3 = "XASjZRV[vwqwOTeczdNUHoR + GRkuieAp](VITSQqAgUbHepYo + fzqVK, rWyJSrLIc + OEWazIbswctA + Qba + FLrJJnYG + AfdTDPrnhbYBb + UFC + Q" ascii
    $s4 = "function suBIZR(n){return AgQgDc + JJBNudaAkvGPr + CNKDwybxLfVeiBy + xrtksEXSQw + fTSYgxTPI + wGilWXtx + PbGaNEXfb;}" fullword ascii
    $s5 = "uerqZbXV + CqWyqUpQ + ttuypne + uItdXQjXhClGWc + SZml + AGvBnkqDy + zkpbOx + kfXTVMpKlnvhDy + gqiRNqsemTybBFu, false);" fullword ascii
    $s6 = "var RIZeSyBC = new Date();" fullword ascii
    $s7 = "function uYkWMVApg(SDZLxW){gtigtSqsD[fFdBBAKF](SDZLxW, 0, 0);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}