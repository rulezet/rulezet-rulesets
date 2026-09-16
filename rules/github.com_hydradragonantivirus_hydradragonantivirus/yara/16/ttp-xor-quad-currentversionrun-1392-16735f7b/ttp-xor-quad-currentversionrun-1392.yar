rule TTP_XOR_QUAD_CurrentVersionRun_1392 {
  strings:
    $key_1392 = { 40 fd [2] 64 f3 [2] 4f df [2] 61 fd [2] 75 e6 [2] 7a fc [2] 64 e1 [2] 66 e0 [2] 7d e6 [2] 61 e1 [2] 7d ce }

  condition:
    any of them
}