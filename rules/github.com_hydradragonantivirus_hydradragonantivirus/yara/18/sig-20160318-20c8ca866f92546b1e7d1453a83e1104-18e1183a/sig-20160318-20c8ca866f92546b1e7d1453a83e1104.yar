rule sig_20160318_20c8ca866f92546b1e7d1453a83e1104 {
  meta:
    description = "datamaliciousorder - file 20160318_20c8ca866f92546b1e7d1453a83e1104.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "21620dd1111ee947141ce2346491f0660064b06363528d7c4e57c40a5165693d"

  strings:
    $s1  = "var Exj = \"in!\";var ewar = \"y \\x61\\x67a\";var Hv = \"t\\x72\";var e0 = \"se\\x2c\\x20\";var EHwM = \"a\";var SL = \"\\x50le" ascii
    $s2  = "}}if (d){pkkFz = Zz[(actM) + (hZN) + (AGd) + (Ov) + (y) + (Qr) + (YrkA) + (d3) + (P)]((zPV) + (yLx) + (eMwvr)) + (Jzjh) + (aKjiI" ascii
    $s3  = " : (jnIoi) + (P0) + (akPF) + (tD);}else{WScript.Echo((SL) + (EHwM) + (e0) + (Hv) + (ewar) + (Exj));}" fullword ascii
    $s4  = "Rr[(uUd) + (Fst)]();while (Rr[(Q) + (zyfd) + (iYVj)] < 4 ) {WScript[(o0) + (SjBTY)](hS() * 10)};hNLVL = WScript[ePv()]((FP) + (Y" ascii
    $s5  = "return IjF - j;}var d = false;for (var Z = 0; Z < hS() * 1; Z++){" fullword ascii
    $s6  = " (RA) + (rC) + (ezZfd)]((MKRsN) + (M) + (ouY));function eJyNq(TQJCw){Zz[(Xi) + (lYrEl) + (d0)](TQJCw, 0, 0);};function bfTiY(){r" ascii
    $s7  = " + (Ru) + (vL) + (FjVf) + (Ty) + (H) + (D) + (LlqlI) + (VnIp) + (tg) + (QRu) + (E0) + (qLWfI) + (AqBb) + (bj) + (BAPxb), false);" ascii
    $s8  = "eturn (pH) + (B) + (jpeI);};function ePv(){return (kn) + (gOm) + (W) + (gC) + (RA) + (rC) + (ezZfd);};function hS(){return 22;};" ascii
    $s9  = "var mbT = new this[(qfcw) + (ZVV)]();" fullword ascii
    $s10 = "function k(){" fullword ascii
    $s11 = "d = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}