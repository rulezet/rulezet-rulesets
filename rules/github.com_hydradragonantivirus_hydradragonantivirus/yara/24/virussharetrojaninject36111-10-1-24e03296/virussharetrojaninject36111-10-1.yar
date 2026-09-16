rule VirusShareTrojanInject36111_10_1 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanInject36111_10_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cdab15a6474be4dbc21da10db4dd73728ac5c9e35a03f486e3dfd19a3c794b0e"

  strings:
    $s1 = "soLI@SmPVV_vr9800629800629800629800629800629800629800629800629800629800629800629800629800629800629800629800629800629800629800629" ascii
    $s2 = "soLI@SmPVV_vr9800629800629800629800629800629800629800629800629800629800629800629800629800629800629800629800629800629800629800629" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}