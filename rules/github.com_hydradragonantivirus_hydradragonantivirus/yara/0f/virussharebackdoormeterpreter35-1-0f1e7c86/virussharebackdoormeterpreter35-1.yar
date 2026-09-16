rule VirusShareBackDoorMeterpreter35_1 {
  meta:
    description = "datamaliciousorder - file VirusShareBackDoorMeterpreter35_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "75e2177822d6f3d14e447cb681b527fd9a8f9b1703618328faefcecabdc91be9"

  strings:
    $s1 = "LBuilt using an evaluation version of {smartassembly}. Cannot be distributed." fullword ascii
    $s2 = " exile" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}