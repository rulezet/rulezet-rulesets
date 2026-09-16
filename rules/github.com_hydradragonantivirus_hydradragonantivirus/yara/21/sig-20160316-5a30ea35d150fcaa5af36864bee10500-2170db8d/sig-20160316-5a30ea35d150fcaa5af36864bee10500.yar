rule sig_20160316_5a30ea35d150fcaa5af36864bee10500 {
  meta:
    description = "datamaliciousorder - file 20160316_5a30ea35d150fcaa5af36864bee10500.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "09ec0cefa677c83ca550a2d0bd04f5936b868d37f592aab5b473df4ad83e45e3"

  strings:
    $s1 = "while (JlyvaUw[vJfRqvxMba + jtOg + RjnqfHiCWvbXRk + diVwk + VfyXWJN] < 4 ) {WScript[TCOnfKPUkxxtxzS + avIQx + nxWl](1000)};" fullword ascii
    $s2 = "function Dtc(n){return yKwLzyWpicwF + idTxQc + RgyxpLgNUbG + aMAW + cclbwL + YypQ + dfeRyVNbL;}" fullword ascii
    $s3 = "function uuRZw(UaqrbbPieLTUXC){UVrDgpz[VgUpHFUbcEVC + acxlqxGl](UaqrbbPieLTUXC, 0, 0);}" fullword ascii
    $s4 = "var kFIYHJGTRZyiXOT = new Date();" fullword ascii
    $s5 = "JlyvaUw[moNlNWQaL + MiktTgXEcqUNu](nmbrYmj + UNeQGqlgv + YlyAFENKWaP, Lox + gVdlrhnYh + yUcakEWgQiqUJ + oCTJcDgpTs + GOtpZ + xJu" ascii
    $s6 = "N, false);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}