import "pe"
rule _VirusShareTrojanSiggen1961528_5_1_VirusShareTrojanSiggen1961528_19 {
  meta:
    description = "datamaliciousorder - from files VirusShareTrojanSiggen1961528_5_1.vir, VirusShareTrojanSiggen1961528_6_1.vir, VirusShareTrojanSiggen1961528_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "95fa824c9b47e1947efb34204c96a337a36bf2aba590b1b6beaebf4e34431eb6"
    hash2       = "341609ffb3776278e854c202795a154f77fc4ba9ff1a4e4e129ac0cfae202c54"
    hash3       = "9b6cc6f14903052274a8809b68aebf044ed5f90ab0d85b38ac59c5b967116594"

  strings:
    $s1 = "D#comment" fullword wide
    $s2 = "StormLib v 9.22 Copyright Ladislav Zezula 1998-2014" fullword ascii
    $s3 = "D#document" fullword wide
    $s4 = "Cxml:base" fullword wide
    $s5 = "D#text" fullword wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "2ff9b66b8a02549cbf4e6f6db5c2419b" and (all of them)
    ) or (all of them)
}