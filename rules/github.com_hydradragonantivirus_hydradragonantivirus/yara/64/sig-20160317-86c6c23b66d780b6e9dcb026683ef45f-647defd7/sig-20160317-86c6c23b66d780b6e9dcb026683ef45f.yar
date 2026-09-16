rule sig_20160317_86c6c23b66d780b6e9dcb026683ef45f {
  meta:
    description = "datamaliciousorder - file 20160317_86c6c23b66d780b6e9dcb026683ef45f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3684d52f32f59c241f0c90d0ca0e654b9e267ed6f410709c6dc998b71f5d2ff8"

  strings:
    $s1  = "var kaik = \"n!\";var FB = \"\\x20agai\";var g = \", t\\x72\\x79\";var Bl = \"ase\";var iFkyf = \"\\x50l\\x65\";var RZLr = \"16" ascii
    $s2  = ") : (irP) + (fxucM) + (RZLr);}else{WScript.Echo((iFkyf) + (Bl) + (g) + (FB) + (kaik));}" fullword ascii
    $s3  = "}}if (tMk){OiyjW = R[(qgR) + (My) + (nXy) + (Xfj) + (HU) + (gB) + (jCKib) + (i)]((IM) + (ndhpr)) + (cF) + (NWZb) + (P) + (NRatZ)" ascii
    $s4  = "Script[(FfL) + (YTjLD) + (mC) + (IcOV) + (GW)]((f) + (mbNHN) + (oFCr) + (xp));function Sml(lDOIQ){R[(wIJQ)](lDOIQ, 0, 0);};funct" ascii
    $s5  = "return bG - TQ;}var tMk = false;for (var FeUnF = 0; FeUnF < NT() * 1; FeUnF++){" fullword ascii
    $s6  = "ion a(){return (b) + (UHJV) + (eZL) + (p) + (icd);};function KrR(){return (FfL) + (YTjLD) + (mC) + (IcOV) + (GW);};function NT()" ascii
    $s7  = "t) + (w) + (We) + (Rwf) + (gTyqx) + (gj) + (DBhJQ) + (PDOUH), false);ZbP[(v) + (QXHJS)]();while (ZbP[(LqT) + (SrG) + (OJZ) + (ts" ascii
    $s8  = "{return 22;};function KMEk(){" fullword ascii
    $s9  = "var J = new this[(B)]();" fullword ascii
    $s10 = "var kaik = \"n!\";var FB = \"\\x20agai\";var g = \", t\\x72\\x79\";var Bl = \"ase\";var iFkyf = \"\\x50l\\x65\";var RZLr = \"16" ascii
    $s11 = "tMk = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}