rule sig_20160315_2d612cd4ad0cc05e90e5e528244a75ae {
  meta:
    description = "datamaliciousorder - file 20160315_2d612cd4ad0cc05e90e5e528244a75ae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ddcba5ec04956c760aa86a119c54942e3e9baaa282eced94de87cb7eca60f422"

  strings:
    $s1 = "function otKSnRhqULvNE(wczPktVtohnje){WshShell[fVd + UxgJyeLYuVwLY + MVFbldLRfMxQ](wczPktVtohnje, 0, 0);}" fullword ascii
    $s2 = "while (VmoRDjoqoKh.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s3 = "function dvwGNP(n){return fvATSuBrCVEbpdN + JKOZltUSuvtO + tZUNnvcEKE + obsXaWd + NFHZgAIkevBoxA + agwHUTct + ucWp + uoxRZcNGQ +" ascii
    $s4 = "VmoRDjoqoKh[MamI + nsRA](AsgxBzxoUUQIXvd + IdDXJ, gspgd + KKFkeZKQhpDGj + mPZNwqpyzF + mIT + ddx0 + GKhLWHJAr + PjXxLwkPZVrz + q" ascii
    $s5 = "dTqpXlFzwez + tfNLNuniLilmz, false);" fullword ascii
    $s6 = "function dvwGNP(n){return fvATSuBrCVEbpdN + JKOZltUSuvtO + tZUNnvcEKE + obsXaWd + NFHZgAIkevBoxA + agwHUTct + ucWp + uoxRZcNGQ +" ascii
    $s7 = "var zds = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}