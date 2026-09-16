rule TTP_XOR_QUAD_CurrentVersionRun_2392 {
  strings:
    $key_2392 = { 70 fd [2] 54 f3 [2] 7f df [2] 51 fd [2] 45 e6 [2] 4a fc [2] 54 e1 [2] 56 e0 [2] 4d e6 [2] 51 e1 [2] 4d ce }

  condition:
    any of them
}