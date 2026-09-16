rule sig_20160315_c5e1b83afb32e0bbd3f1cc3f92241e8a {
  meta:
    description = "datamaliciousorder - file 20160315_c5e1b83afb32e0bbd3f1cc3f92241e8a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0e9b154b591b4b256d6532493367cfc8f009100350701f8faaf4e1c28c9ba3ad"

  strings:
    $s1 = "function FlPBqQ(CGVssxDpQKPWiWc){WshShell[HESAZOkI + SfvXzcO](CGVssxDpQKPWiWc, 0, 0);}" fullword ascii
    $s2 = "while (jJnGIiGjhW.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s3 = "function CnNhDTz(n){return MVswHnQFLflG + IrKllFKzd + xBbSAcHZk + OiOgkZ + PHKbmUezOwQnS + HoZJA;}" fullword ascii
    $s4 = "bgw + ylun + ImWsuTKhtCOYqS + DVRG, false);" fullword ascii
    $s5 = "jJnGIiGjhW[XWHcSrY + DageBbpICQt](NggaXRGXAimaLNu + pgRpgO, EqWfRlLqEuXaY + riFtOtjuqwKNNd + JbqcJdjndwIc + PwzkOZEUoVp + rkrAvT" ascii
    $s6 = "var NBYLBqNeMjEdYCK = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}