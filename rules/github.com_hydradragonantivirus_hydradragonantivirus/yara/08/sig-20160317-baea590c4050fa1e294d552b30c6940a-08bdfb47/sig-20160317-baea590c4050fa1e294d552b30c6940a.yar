rule sig_20160317_baea590c4050fa1e294d552b30c6940a {
  meta:
    description = "datamaliciousorder - file 20160317_baea590c4050fa1e294d552b30c6940a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "873189e75167138b0fffb6b652d9d2ba9cd062ba5c5e13698e5354791eacaa21"

  strings:
    $s1  = "var wfKDn = \"ga\\x69n!\";var Gx = \" \\x61\";var UNH = \"r\\x79\";var FNTHU = \"xMdtvqcy\".charAt(3);var B = \"2GQ bVG\".charAt" ascii
    $s2  = "(jUMRi)]();while (hTgF[(W0) + (BZ) + (s) + (QDgd)] < 4 ) {WScript[(WFa)](YUAs() * 10)};WQd = WScript[n()]((vpI) + (fFCSe) + (BRQ" ascii
    $s3  = "WEVn = WScript[(h) + (Kx) + (yD) + (wiu) + (mD)]((DEh) + (Ke) + (i) + (BCpeC));function nVZHU(dAVM){mWEVn[(lLG) + (PNAJ)](dAVM, " ascii
    $s4  = " (e0);}else{WScript.Echo((Cmtv) + (kud) + (B) + (FNTHU) + (UNH) + (Gx) + (wfKDn));}" fullword ascii
    $s5  = "return EQvp - E;}var PtLZ = false;for (var Phs = 0; Phs < YUAs() * 1; Phs++){" fullword ascii
    $s6  = "}}if (PtLZ){DKBdL = mWEVn[(p0) + (StvV) + (yELF) + (ycPOM) + (KP) + (XqLt) + (fQwPC) + (dD) + (a)]((eV) + (mZrne) + (W) + (WDevi" ascii
    $s7  = "(uRc) + (oE) + (A) + (XdFwI) + (tfH) + (GfzfR) + (gsM) + (PIieH) + (Fl) + (p1) + (AtXXd) + (c0) + (XRqzK), false);hTgF[(selv) + " ascii
    $s8  = "0, 0);};function uDAz(){return (v) + (AV) + (SJu) + (M);};function n(){return (h) + (Kx) + (yD) + (wiu) + (mD);};function YUAs()" ascii
    $s9  = "{return 22;};function Mn(){" fullword ascii
    $s10 = "PtLZ = true;" fullword ascii
    $s11 = "var TTlKq = new this[(kEonc)]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}