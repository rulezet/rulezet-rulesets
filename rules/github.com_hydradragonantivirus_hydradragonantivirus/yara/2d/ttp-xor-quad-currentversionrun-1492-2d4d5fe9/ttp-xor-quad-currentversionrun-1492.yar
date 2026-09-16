rule TTP_XOR_QUAD_CurrentVersionRun_1492 {
  strings:
    $key_1492 = { 47 fd [2] 63 f3 [2] 48 df [2] 66 fd [2] 72 e6 [2] 7d fc [2] 63 e1 [2] 61 e0 [2] 7a e6 [2] 66 e1 [2] 7a ce }

  condition:
    any of them
}