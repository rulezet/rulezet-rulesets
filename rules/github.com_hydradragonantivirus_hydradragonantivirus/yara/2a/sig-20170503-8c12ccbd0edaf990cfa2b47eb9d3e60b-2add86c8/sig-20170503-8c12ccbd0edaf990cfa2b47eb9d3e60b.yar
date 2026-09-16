rule sig_20170503_8c12ccbd0edaf990cfa2b47eb9d3e60b {
  meta:
    description = "datamaliciousorder - file 20170503_8c12ccbd0edaf990cfa2b47eb9d3e60b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6a96b466b29f47935ad692f24304c83e624faa90289371383b1c713661288a68"

  strings:
    $s1 = "if (lTebXGcOWRtVEqds() == false) {" fullword ascii
    $s2 = "return eUAfRNPLynpWFSEczQo.replace(RegExp(sSrHbyCUGYTDMEVgB, \"g\"), OfAtDpyVaMjwlodqnz); }" fullword ascii
    $s3 = "function BLHthOozbmXUVxrTua(eUAfRNPLynpWFSEczQo, sSrHbyCUGYTDMEVgB, OfAtDpyVaMjwlodqnz) { " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}