rule TTP_XOR_QUAD_CurrentVersionRun_1692 {
  strings:
    $key_1692 = { 45 fd [2] 61 f3 [2] 4a df [2] 64 fd [2] 70 e6 [2] 7f fc [2] 61 e1 [2] 63 e0 [2] 78 e6 [2] 64 e1 [2] 78 ce }

  condition:
    any of them
}