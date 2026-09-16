rule sig_20160317_27bcd98ecae8832001b0599696f4ddbd {
  meta:
    description = "datamaliciousorder - file 20160317_27bcd98ecae8832001b0599696f4ddbd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8ea633af3aa569c0667a28faaab7bf9aa1c0b8617b78e408475a113ac9490b76"

  strings:
    $s1  = "var a1 = \"\\x69\\x6e\\x21\";var a0 = \"\\x67a\";var mnSS = \" \\x61\";var TK = \"\\x79\";var FTvm = \"\\x72\";var XSfJJ = \"e," ascii
    $s2  = "}}if (FA){bW = GudFR[(X) + (AsxT) + (wUi) + (UWhf) + (O) + (eE) + (CqPM) + (PXf) + (l)]((U) + (Ch)) + (s) + (t) + (irP) + (YNvr)" ascii
    $s3  = ") + (N0) + (yE) + (ais) + (T) + (JqimJ), false);KIt[(GWrd) + (wQJ)]();while (KIt[(Xguws) + (zjV) + (CoLq)] < 4 ) {WScript[(c) + " ascii
    $s4  = ") + (IYi) + (qPLP);}else{WScript.Echo((hi) + (XSfJJ) + (FTvm) + (TK) + (mnSS) + (a0) + (a1));}" fullword ascii
    $s5  = "R = WScript[(pwB) + (zftqY) + (up) + (i)]((ZT) + (Qpk) + (sRfl) + (lUJ) + (rps));function Vezul(bL){GudFR[(ehv) + (JJP)](bL, 0, " ascii
    $s6  = "return S - jQSH;}var FA = false;for (var ZoO = 0; ZoO < n() * 1; ZoO++){" fullword ascii
    $s7  = "var p = new this[(DjgG) + (io)]();" fullword ascii
    $s8  = "0);};function Qvfv(){return (GyY) + (ix) + (G) + (oq);};function QvxB(){return (pwB) + (zftqY) + (up) + (i);};function n(){retur" ascii
    $s9  = "n 22;};function kd(){" fullword ascii
    $s10 = "FA = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}