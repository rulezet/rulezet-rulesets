rule Trojan_Autorun_Gen_Heur_Mint_Zard_40 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Zard.40.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4ad4121fded24daacc511a49e5abe83aa9ff0b8c0ea9c5196d87a34e4919b6e4"

  strings:
    $s1 = "(char)('d_X" fullword ascii
    $s2 = "nknown exception}" fullword ascii
    $s3 = "?length" fullword ascii
    $s4 = "Te Path" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}