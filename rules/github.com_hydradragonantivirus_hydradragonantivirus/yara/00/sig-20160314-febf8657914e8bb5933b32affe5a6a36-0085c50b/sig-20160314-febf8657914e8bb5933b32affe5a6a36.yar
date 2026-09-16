rule sig_20160314_febf8657914e8bb5933b32affe5a6a36 {
  meta:
    description = "datamaliciousorder - file 20160314_febf8657914e8bb5933b32affe5a6a36.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "141272a6673287a25757d06a5222ddd0c4313c512d2cd159641c0949b0e9c392"

  strings:
    $s1 = "while (zEXPQwIyq.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s2 = "return ERKJPFf + KgeuDfj + ntJeXqrfEQ + elZVZGAcOTfQbY + qynRwykTDdc + NiQjfLUvQOVe + nRkQQgnIrdzhZc" fullword ascii
    $s3 = " RKlcLrnoJ + mLrVjoRnoEtki + EcCTfTRLE + IXtKVNCgRYlr + BgelFams, false);" fullword ascii
    $s4 = "zEXPQwIyq.open(VCAENwaUewgeJy + wGAfvbOYpYAHo, xVUHKWtVeJCXEv + TVo + WJduHTUJePip + ZOHuBftXK + wetqUB + dzjy + YZfDFgsbLIzDP +" ascii
    $s5 = "function TLKmzdIA(n)" fullword ascii
    $s6 = "var sAzEqpNlWgU = new Date();" fullword ascii
    $s7 = "function mFhfqVKDz(fname)" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}