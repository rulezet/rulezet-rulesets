rule sig_20160314_71feb0e071210cd005b1c4974080dc1a {
  meta:
    description = "datamaliciousorder - file 20160314_71feb0e071210cd005b1c4974080dc1a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d53a5f329b57ca47e2474a5cba2e2759c7be01f475c5e8e289e7810da6715bbb"

  strings:
    $s1 = "IAnqnnBJ.open(GLBGXmXB + Ywg, dHdMotQEEzqUH + YmKacGmCIVpDnmB + auZZSnzEqY + DbsLjCeV + pjYaAtyWrvqnL + SAIwnxcoqkaR + NHjZxu + " ascii
    $s2 = "while (IAnqnnBJ.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s3 = "+ zJVzMXvgeWxOs + vShUAKm + ykAbqju + xMwsPVceblMeXER + WJgkIJygECjWS + kiqhCcLaBmcN + QUfJLAv + AycsrPKlD, false);" fullword ascii
    $s4 = "return YxOebVHtHCc + Pez + oZRQi + nPaFoHoqx + nyMCjOPu + wUJOlPxzRXno + UFjGAx" fullword ascii
    $s5 = "function TUrKtILEl(n)" fullword ascii
    $s6 = "function koVyoXVFFoR(fname)" fullword ascii
    $s7 = "var JqULzEy = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}