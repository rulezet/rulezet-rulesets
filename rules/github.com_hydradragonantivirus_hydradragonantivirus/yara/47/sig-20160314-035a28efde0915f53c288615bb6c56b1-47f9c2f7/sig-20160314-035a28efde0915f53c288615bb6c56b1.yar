rule sig_20160314_035a28efde0915f53c288615bb6c56b1 {
  meta:
    description = "datamaliciousorder - file 20160314_035a28efde0915f53c288615bb6c56b1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eb0c1e5091dd051f0b2ea060313b81c640e1b1f8aa834b8f2187facb751d86fd"

  strings:
    $s1 = "CsY.open(ZeSvDM, RPD + grV + yiiKuVQsTnD + ObbbQ + jNO + fVbryVHvkW + hoz + GebTEQIRKKQI + fbGrOYyFKr + nSwtQSIVRGO + WrbLFoAKTz" ascii
    $s2 = "while (CsY.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s3 = "return BgTuTeB + WRBph + JEHfcuoZFEjVf + KmYPr + Ziuw + NgodAXkXhy" fullword ascii
    $s4 = " + asKKcEyCDJ + akehfyfJuDFIS + bnEiWQGBsxZZwW + hvBZoRvRkImKcN + CYza, false);" fullword ascii
    $s5 = "var ReRQjLfIa = new Date();" fullword ascii
    $s6 = "function WAWs(fname)" fullword ascii
    $s7 = "function kmKyiwRlgwxms(n)" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}