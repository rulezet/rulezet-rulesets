rule sig_20160317_36e752e74336e7e365575a615d378dad {
  meta:
    description = "datamaliciousorder - file 20160317_36e752e74336e7e365575a615d378dad.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2daa5699e71b58bfb27f3a15bb7a253a4a157220b4d5fbd51f06bccf34163f50"

  strings:
    $s1 = "var P = \"8!F\".charAt(1);var BPFVi = \"g\\x61\\x69\\x6e\";var dWNA = \"\\x74ry\\x20a\";var wayyW = \"s\\x65, \";var Efr = \"Ple" ascii
    $s2 = "}else{WScript.Echo((Efr) + (wayyW) + (dWNA) + (BPFVi) + (P));}" fullword ascii
    $s3 = "return B - f;}var e = false;for (var ERcxb = 0; ERcxb < 10; ERcxb++){" fullword ascii
    $s4 = "}}if (e){bKGQp = MVttQ[(rhEog) + (wXaZd) + (oqg) + (v) + (Rxykw) + (JI) + (SKi) + (kk) + (Ei)]((Wb) + (Km)) + (pu) + (ZCEO) + (k" ascii
    $s5 = "var eor = new this[(KhYH) + (lGurV) + (MHkYR)]();" fullword ascii
    $s6 = "t)](gpx, 0, 0);};function o(){return (eLGHu) + (icL) + (seBuV) + (evs) + (EL) + (MQ);};function YhiLw(){return (lApH) + (uDxF) +" ascii
    $s7 = " (UzL) + (WKrJ) + (CBaC) + (D);};function ZBz(){return 22;};function nbGd(){" fullword ascii
    $s8 = "t[(lApH) + (uDxF) + (UzL) + (WKrJ) + (CBaC) + (D)]((WLqXJ) + (U) + (vBbs) + (HJXI) + (tpIZ) + (faA));function bcE(gpx){MVttQ[(ZR" ascii
    $s9 = "(CKMEv)]((Ggsj), (J) + (XJfrM) + (wfWl) + (a0) + (eji) + (CnpG) + (rrt) + (GNUVn) + (cYZ) + (HluHb), false);kzl[(fHEO)]();while " ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}