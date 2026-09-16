rule Trojan_Hooker_Win32_Brontok_AP_mm {
  meta:
    description = "datamaliciousorder - file Trojan.Hooker_Win32.Brontok.AP@mm.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "228d579023698f4660b129d48f8cd15d500931b65d52c85afb79df598af56bbf"

  strings:
    $s1 = "BackDown" fullword ascii
    $s2 = "Brontok.A3 Browser" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}