rule sig_20160317_46bf26328f6647b22718ad2033a9a840 {
  meta:
    description = "datamaliciousorder - file 20160317_46bf26328f6647b22718ad2033a9a840.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c2696635a618115dc900ffbfe4ba5a9044b6dc0208d5b03d1ad3a8ce74f0614c"

  strings:
    $s1  = "var SoI = \"v!VA\".charAt(1);var Uf = \"again\";var KbcHI = \" try \";var S = \"\\x73\\x65,\";var vuMHZ = \"aHam35s\".charAt(2);" ascii
    $s2  = " + (l1);}else{WScript.Echo((JPp) + (vuMHZ) + (S) + (KbcHI) + (Uf) + (SoI));}" fullword ascii
    $s3  = "x32.\\x58\";var aoyNm = \"SXML\";var nKYO = \"HgcgM\".charAt(4);var f = \"Run\";var ky = \"ll\";var fVLXW = \"\\x68\\x65\";var b" ascii
    $s4  = "return guNE - kHbo;}var d = false;for (var QFmJ = 0; QFmJ < R() * 1; QFmJ++){" fullword ascii
    $s5  = "}}if (d){EMTD = iHI[(h) + (Nxw) + (u) + (AGGo) + (G) + (gn) + (TmD) + (eYQ) + (gHlO) + (QF)]((SA) + (VVsEL)) + (Gnl) + (IZWp) + " ascii
    $s6  = ";uIk[(OwCE)]((qkJlk) + (dw), (crJma) + (l) + (UgW) + (we) + (qkij) + (A) + (OWC) + (tCZio) + (ApoV) + (A0), false);uIk[(i)]();wh" ascii
    $s7  = "Jr) + (CP) + (bate) + (fVLXW) + (ky));function I(hxE){iHI[(f)](hxE, 0, 0);};function ZhBzh(){return (nKYO) + (aoyNm) + (FwkZ) + " ascii
    $s8  = "(Yn) + (xVZXr) + (ELj);};function NZmRD(){return (um) + (MgB) + (gdRs) + (b) + (yeOPd) + (BYOoc);};function R(){return 22;};func" ascii
    $s9  = "var Hbde = new this[(LYxD)]();" fullword ascii
    $s10 = "d = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}