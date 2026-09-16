rule TTP_XOR_QUAD_CurrentVersionRun_b492 {
  strings:
    $key_b492 = { e7 fd [2] c3 f3 [2] e8 df [2] c6 fd [2] d2 e6 [2] dd fc [2] c3 e1 [2] c1 e0 [2] da e6 [2] c6 e1 [2] da ce }

  condition:
    any of them
}