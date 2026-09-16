rule sig_20160317_4f5318bc50817fffefb8e71040815413 {
  meta:
    description = "datamaliciousorder - file 20160317_4f5318bc50817fffefb8e71040815413.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ba76f2ebbfdb88be4f9428bb3902c9e3d1ec22865d101eaac6a044b94a008372"

  strings:
    $s1  = "var zPNZ = \"\\x61in!\";var AykZx = \"E6gYexL\".charAt(2);var qnWko = \"\\x79\\x20a\";var oR = \", t\\x72\";var nGEdN = \"CSewGi" ascii
    $s2  = ", false);fYGzj[(gtnWA)]();while (fYGzj[(cZM) + (LxX) + (J)] < 4 ) {WScript[(dq) + (QT)](qk() * 10)};qPPa = WScript[d()]((RqfET) " ascii
    $s3  = "KbEB ? (Z) + (qu) + (vr) + (CkXV) : (FLwX) + (enYC) + (a0);}else{WScript.Echo((i0) + (nGEdN) + (oR) + (qnWko) + (AykZx) + (zPNZ)" ascii
    $s4  = "return i - ujNbE;}var UKbEB = false;for (var uu = 0; uu < qk() * 1; uu++){" fullword ascii
    $s5  = "}}if (UKbEB){JWpsH = JE[(BalQc) + (OL) + (u) + (hrwSj) + (ImewG) + (fpB) + (Ypxo) + (o) + (u0) + (t) + (soEn)]((bJlB) + (g) + (W" ascii
    $s6  = "+ (chYRU) + (jhP);};function d(){return (aY) + (ZDdzZ) + (Unyc);};function qk(){return 22;};function QP(){" fullword ascii
    $s7  = ")]((BTJi) + (hSVOj) + (na) + (Ccdt) + (WOO));function W(hGVqt){JE[(rg)](hGVqt, 0, 0);};function I(){return (gzfF) + (ib) + (Gz) " ascii
    $s8  = "UKbEB = true;" fullword ascii
    $s9  = ";W(JWpsH);i = \"\" + (PgN) + (wYONS) + (jzbVo) + (qoPH) + (boT) + (im) + (CA) + (vKFpJ) + (geA) + (n0) + (faz) + (uaxW) + (QY) +" ascii
    $s10 = "var vKFpJ = \"\\x64\\x38fa\";var CA = \"u\\x37\\x68gs\";var im = \"a\";var boT = \"df\";var qoPH = \"\\x61\\x6fs\";var jzbVo = " ascii
    $s11 = "var caB = new this[(Y)]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}