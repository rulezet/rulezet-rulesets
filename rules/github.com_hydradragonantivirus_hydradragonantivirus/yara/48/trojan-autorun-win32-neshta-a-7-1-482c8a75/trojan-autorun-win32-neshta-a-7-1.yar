rule Trojan_Autorun_Win32_Neshta_A_7_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Win32.Neshta.A_7_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "df47f3f02c3563d6ab0941c855b2cfc63a9be3c4bfd8c857aad6d0e12c294f4b"

  strings:
    $s1 = "aOrders: is defined as the total number of distinct orders for all programs that are a part of Electronic Orders, entered" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}