rule TTP_XOR_QUAD_CurrentVersionRun_0392 {
  strings:
    $key_0392 = { 50 fd [2] 74 f3 [2] 5f df [2] 71 fd [2] 65 e6 [2] 6a fc [2] 74 e1 [2] 76 e0 [2] 6d e6 [2] 71 e1 [2] 6d ce }

  condition:
    any of them
}