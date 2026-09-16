rule Trojan_Hooker_Win32_Floxif_A_29 {
  meta:
    description = "datamaliciousorder - file Trojan.Hooker_Win32.Floxif.A_29.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd51c8f458a37213c7ac8d49dc7b34eada03a69e565226de5d5e5daa08099e1d"

  strings:
    $s1 = "         Values: Unaware, System, PerMonitor -->" fullword ascii
    $s2 = "<description>Volume2</description>" fullword ascii
    $s3 = "<!-- Per Monitor V1 [OS >= Windows 10 Anniversary Update (1607, 10.0.14393, Redstone 1)]" fullword ascii
    $s4 = "         Value: PerMonitorV2 -->" fullword ascii
    $s5 = "<!-- Per Monitor V2 [OS >= Windows 10 Creators Update (1703, 10.0.15063, Redstone 2)]" fullword ascii
    $s6 = "SKUN,]:" fullword ascii
    $s7 = "WORE!hV" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}