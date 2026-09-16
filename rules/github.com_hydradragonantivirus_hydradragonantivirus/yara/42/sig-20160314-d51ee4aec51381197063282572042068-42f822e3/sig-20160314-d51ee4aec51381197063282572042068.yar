rule sig_20160314_d51ee4aec51381197063282572042068 {
  meta:
    description = "datamaliciousorder - file 20160314_d51ee4aec51381197063282572042068.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e35988ab837e55471dc901023d7d15aa967ec915ceca93a65b11b060b3bb17b5"

  strings:
    $s1  = "zDYMhqtMvXV.open(IZFaCCBM + GJa, sUHWhzl + MkceDX + FSfBgKORbesoXsv + ieVxFDIYBXzB + dpdLxoUbp + jDoM + yalLpLftigkdcOa + NNbAmv" ascii
    $s2  = "while (zDYMhqtMvXV.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s3  = "gRfUYkxYNKNz + hxWk + rtSHLpJtfm + bxzzkG + UAbqjXSvXQg + NLcKqNgVZfnZf + arJc + TaN + cOIl, false);" fullword ascii
    $s4  = "return PCKZUHWfpOoT + dDsLcvvoG + bUGkD + DmDjG + IkLWoyvpCqW + HWDJkNnzNpUxJJm + cmbzOaKv" fullword ascii
    $s5  = "GcbYuino + YUpDTsLAugoc + HDOMLYXNnVDXlE + JgrVuBAT + MbOHngaZancbo + gwdnr + gaKE + pAznXM + HsQJuzzgL + grIgRI + SLcLfIMw + Us" ascii
    $s6  = "var grIgRI = \"sy\";" fullword ascii
    $s7  = "function OBnHrxHQRlPUBc(fname)" fullword ascii
    $s8  = "var jBnFuEPjhJMOAP = new Date();" fullword ascii
    $s9  = "function uibF(n)" fullword ascii
    $s10 = "var cOIl = \"g6b\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}