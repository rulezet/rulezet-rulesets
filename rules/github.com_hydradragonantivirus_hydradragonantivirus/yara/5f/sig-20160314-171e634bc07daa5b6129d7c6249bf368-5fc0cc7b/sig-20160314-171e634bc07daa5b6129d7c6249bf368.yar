rule sig_20160314_171e634bc07daa5b6129d7c6249bf368 {
  meta:
    description = "datamaliciousorder - file 20160314_171e634bc07daa5b6129d7c6249bf368.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42990b55f593cc9cca2d5f16d533c17153220437f9ad9de9deb7392547be24dd"

  strings:
    $s1 = "while (InylE.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s2 = "return GyQPowd + mKoC + Coypa + WcNrDzza + KIwyBDsCv + LZeujiwvcHA + Nrg + vJYQg" fullword ascii
    $s3 = "WIPMKLqv + qlEttvJPfdK + GFP, false);" fullword ascii
    $s4 = "InylE.open(LbszBWsAazVq + jItmDZGUlPRps, nAXyHMNdUld + znXcfTCAxmE + SHvtFQOpuHdYavF + gkEjBQuSWbw + GPoH + dQpbUZ + HnaARofMXLv" ascii
    $s5 = "function yTKzx(fname)" fullword ascii
    $s6 = "function xicdZ(n)" fullword ascii
    $s7 = "var TLuGnEVJ = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}