rule sig_20160317_6736d4662380e1c6e11e3cba44421d5b {
  meta:
    description = "datamaliciousorder - file 20160317_6736d4662380e1c6e11e3cba44421d5b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9434072a7d863dee9143f268d14c9c8750652bd2252b6c56a3a67e73ef8bd2e0"

  strings:
    $s1  = "var i = \"!\";var YircH = \"n\";var mrxu = \"aga\\x69\";var z = \"y \";var Tk = \"\\x72\";var t = \"e, t\";var VI = \"P\\x6c\\x6" ascii
    $s2  = "GwrA) + (m) + (MpIt);}else{WScript.Echo((VI) + (t) + (Tk) + (z) + (mrxu) + (YircH) + (i));}" fullword ascii
    $s3  = "}}if (sCONW){KH = ZeD[(diK) + (G0) + (mpQj) + (HHK) + (wtZ) + (GFWHL) + (Cs) + (Ldo) + (UpqIj) + (dYX)]((SMxgh) + (S)) + (iFn) +" ascii
    $s4  = ")]();while (FwrA[(SYMH) + (a) + (lw) + (eLeN) + (bZ) + (iq)] < 4 ) {WScript[(XL) + (KY) + (NF)](V() * 10)};et = WScript[jt()]((n" ascii
    $s5  = "return x - ORAA;}var sCONW = false;for (var gO = 0; gO < V() * 1; gO++){" fullword ascii
    $s6  = "), (BCSNd) + (H) + (Co) + (GucbH) + (Nr) + (vSEhn) + (OB) + (T0) + (SL) + (k) + (iE) + (Nwwd) + (WaFdI), false);FwrA[(b) + (GrED" ascii
    $s7  = "(NmBtg) + (qfjut));function p(LCEvx){ZeD[(B)](LCEvx, 0, 0);};function GEY(){return (qbr) + (Ng) + (NSPke) + (HNiIL) + (pW);};fun" ascii
    $s8  = "ction jt(){return (Aao) + (R) + (YRroB) + (DjGP) + (rQ);};function V(){return 22;};function qDZO(){" fullword ascii
    $s9  = "var ZI = new this[(hilkE)]();" fullword ascii
    $s10 = "sCONW = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}