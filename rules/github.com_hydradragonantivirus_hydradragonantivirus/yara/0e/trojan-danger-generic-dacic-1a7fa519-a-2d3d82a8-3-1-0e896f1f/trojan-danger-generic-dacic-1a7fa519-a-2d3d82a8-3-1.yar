rule Trojan_Danger_Generic_Dacic_1A7FA519_A_2D3D82A8_3_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Generic.Dacic.1A7FA519.A.2D3D82A8_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8bf91b52353802cce2d5913bad59a6aef0c09b82d7d39515d3cabc2344d2cbbc"

  strings:
    $s1 = "Q)University Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}