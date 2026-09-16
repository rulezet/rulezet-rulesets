rule sig_20160317_9020dcc879596dad25773f3c6073f8ed {
  meta:
    description = "datamaliciousorder - file 20160317_9020dcc879596dad25773f3c6073f8ed.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c31becea21bdedb92ecec8bb2bb9e53a59ba0524c13dd621a3b78174ddd572f5"

  strings:
    $s1 = "var afPl = \"n!\";var SrXx = \"ai\";var eYkDJ = \"r\\x79 ag\";var EDLWW = \" t\";var DqE = \"e,\";var arX = \"as\";var X = \"P" ascii
    $s2 = "GHFt) + (N) + (aao) + (ZE) + (jiroR) + (kChkd) + (T0), false);IT[(dB)]();while (IT[(Q0) + (nIHt) + (cB) + (kMF)] < 4 ) {WScript[" ascii
    $s3 = "vQ) + qXX ? (nGfGo) + (Sv) : (cR) + (wO) + (Y) + (wDz);}else{WScript.Echo((X) + (arX) + (DqE) + (EDLWW) + (eYkDJ) + (SrXx) + (af" ascii
    $s4 = "}}if (qXX){YdY = ulQ[(Sq) + (dzx) + (QYgw) + (cY) + (iN) + (qik)]((WQ) + (wEmO) + (V) + (tfUUO)) + (A) + (CBgY) + (yPe) + (m); H" ascii
    $s5 = "x43r\";ulQ = WScript[(ta) + (xDy) + (g) + (j)]((b) + (Zo) + (PGm) + (rgKdf) + (egI));function h(G){ulQ[(i)](G, 0, 0);};function " ascii
    $s6 = "return Qi - gHVo;}var qXX = false;for (var SczE = 0; SczE < rI() * 1; SczE++){" fullword ascii
    $s7 = "(){return (MxC) + (FnJ) + (ox);};function gsG(){return (ta) + (xDy) + (g) + (j);};function rI(){return 22;};function lo(){" fullword ascii
    $s8 = "var UVj = new this[(eBK) + (v)]();" fullword ascii
    $s9 = "qXX = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}