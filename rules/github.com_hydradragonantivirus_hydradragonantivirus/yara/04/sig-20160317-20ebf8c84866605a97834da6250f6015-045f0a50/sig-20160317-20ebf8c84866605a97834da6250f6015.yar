rule sig_20160317_20ebf8c84866605a97834da6250f6015 {
  meta:
    description = "datamaliciousorder - file 20160317_20ebf8c84866605a97834da6250f6015.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bdde1034e00604d422a3f5fd7f3217e6487db1c9d485408b55a703434c2a1704"

  strings:
    $x1 = "var DWStH = \"a\\x69n\\x21\";var xQ = \"\\x61\\x67\";var h0 = \"y\\x20\";var N0 = \"r\";var FS = \"e, t\";var qR = \"eas\";var L" ascii
    $s2 = "(ZmwQ) + (rzQk) + (XZaY) + (mslE) + hm ? (X1) + (kn) : (PtGs) + (lOrmH) + (Ax) + (XRj);}else{WScript.Echo((GrL) + (LbV) + (qR) +" ascii
    $s3 = "}}if (hm){CIUxJ = ixtOG[(tmi) + (KoFR) + (Cdv) + (roJpn) + (qA) + (DGUs)]((TluP) + (x)) + (hbdcN) + (U) + (LD) + (BHI) + (QWw) +" ascii
    $s4 = "return fyqm - VZ;}var hm = false;for (var IZQ = 0; IZQ < ISov() * 1; IZQ++){" fullword ascii
    $s5 = "[(WKCnX) + (MO) + (u) + (j)]((csfw) + (Z) + (OBCe) + (Vu) + (HL));function ylcc(B){ixtOG[(Wl) + (Saa)](B, 0, 0);};function tGjaC" ascii
    $s6 = "var pDUXt = new this[(RvPm) + (yC)]();" fullword ascii
    $s7 = "N) + (O) + (l) + (KhrZQ) + (R0) + (rizA) + (KcbF) + (etoI), false);nu[(WE) + (RR)]();while (nu[(mlV) + (dr) + (ry) + (heIq) + (O" ascii
    $s8 = "(){return (L) + (w) + (pkvF) + (k) + (hU);};function LKGQr(){return (WKCnX) + (MO) + (u) + (j);};function ISov(){return 22;};fun" ascii
    $s9 = "hm = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and all of them
}