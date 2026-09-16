rule sig_20160317_6bd270a7da2647272ee5aae7b501ee77 {
  meta:
    description = "datamaliciousorder - file 20160317_6bd270a7da2647272ee5aae7b501ee77.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "573df86f62af326d69183bf04d2f9b656de9cd8dc2f9c88b417c39ade3ece4e7"

  strings:
    $s1  = "var cGYf = \"in!\";var AEk = \"ga\";var lDGyT = \"y a\";var HZnNY = \"rmTvq\".charAt(0);var xKwD = \", t\";var SuJH = \"l\\x65as" ascii
    $s2  = "arAt(2);Envn = WScript[(Ox) + (VUu) + (SQf) + (huEC) + (Gmk)]((Nw) + (mAc) + (vcAHO) + (EUZYx) + (pSVgE));function bMAR(feqcA){E" ascii
    $s3  = ") + (FzmQo) + (JdSy) + (Fv) + Zl ? (Ujx) + (PBh) : (OcSxu) + (DpHq) + (Ke);}else{WScript.Echo((ybLW) + (SuJH) + (xKwD) + (HZnNY)" ascii
    $s4  = "return iRFf - Dm;}var Zl = false;for (var mi = 0; mi < Xi() * 1; mi++){" fullword ascii
    $s5  = "}}if (Zl){AOE = Envn[(w) + (DnM) + (aI) + (m0) + (Bd) + (N) + (Kz) + (Gcw) + (WI)]((LLwub) + (lDDlV) + (JHzjj)) + (Tt) + (Imvya)" ascii
    $s6  = " + (Ca) + (Siqua) + (NXH) + (jq) + (W) + (ieDF) + (qce), false);MFv[(s)]();while (MFv[(EJMi) + (DfjyL) + (C)] < 4 ) {WScript[(Ck" ascii
    $s7  = "var Zhcs = new this[(sIqt) + (pBUMH)]();" fullword ascii
    $s8  = "Mg) + (i)](MFv[(eK) + (W0) + (Bry) + (i0) + (QuIs) + (Bc)]);Ys[(RSuHN) + (TWV) + (YlFsO)] = 0;Ys[(eOk) + (vj) + (JkK) + (KXym) +" ascii
    $s9  = "huEC) + (Gmk);};function Xi(){return 22;};function E(){" fullword ascii
    $s10 = "nvn[(vRT)](feqcA, 0, 0);};function BqYw(){return (F) + (yK) + (FGGwt) + (tcWVe);};function omX(){return (Ox) + (VUu) + (SQf) + (" ascii
    $s11 = "\"\\x70osi\";var Bc = \"y\";var QuIs = \"d\";var i0 = \"s\\x65\\x42o\";var Bry = \"on\";var W0 = \"es\\x70\";var eK = \"R\";var " ascii
    $s12 = "Zl = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}