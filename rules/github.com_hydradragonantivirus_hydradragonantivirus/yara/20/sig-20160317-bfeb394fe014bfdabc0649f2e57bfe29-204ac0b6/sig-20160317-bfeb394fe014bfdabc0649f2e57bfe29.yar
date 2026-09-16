rule sig_20160317_bfeb394fe014bfdabc0649f2e57bfe29 {
  meta:
    description = "datamaliciousorder - file 20160317_bfeb394fe014bfdabc0649f2e57bfe29.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a44aa5cbbdc668648d6e41580bdf527f0e923c0cbc6e77f5a619253259eab2d"

  strings:
    $s1  = "var sg = \"\\x6e!\";var i0 = \"\\x61gai\";var D0 = \"ry \";var ihAs = \"\\x65,\\x20\\x74\";var XFXb = \"Pl\\x65as\";var dEb = \"" ascii
    $s2  = ") + (b) + (btUD) + (TGlTu) + (NzfW) + (cUdNp) + (oB) + (oEL) + gp ? (mbkt) + (Tr) : (FL) + (dEb);}else{WScript.Echo((XFXb) + (ih" ascii
    $s3  = "}}if (gp){Bt = fLO[(SvID) + (bmKlx) + (P) + (uJc) + (QS) + (qGfZ) + (ppT) + (jt) + (m)]((zoE) + (mSqN) + (gRJ)) + (rXxfu) + (o) " ascii
    $s4  = "var W = \"Cr\\x65\";fLO = WScript[(W) + (BKiL) + (rQYf) + (TSD)]((YrR) + (YB) + (Ggr) + (umhH) + (kTRWr));function PG(WTCXO){fLO" ascii
    $s5  = "return kULtV - lYzR;}var gp = false;for (var PA = 0; PA < FECXs() * 1; PA++){" fullword ascii
    $s6  = "sl) + (FxMUi)](WTCXO, 0, 0);};function dtjG(){return (dg) + (Ev) + (lOe) + (NYFpy) + (HwRDu);};function xCW(){return (W) + (BKiL" ascii
    $s7  = ") + (rQYf) + (TSD);};function FECXs(){return 22;};function xB(){" fullword ascii
    $s8  = "hO) + (haCE) + (MECJ) + (uNxhx) + (gH) + (gu) + (PdpJ) + (De), false);ZaUO[(ZKq) + (z)]();while (ZaUO[(r) + (n) + (Ck) + (QFVG) " ascii
    $s9  = "var X = new this[(x)]();" fullword ascii
    $s10 = "gp = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}