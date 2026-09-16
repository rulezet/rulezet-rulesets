rule TTP_XOR_QUAD_CurrentVersionRun_bc92 {
  strings:
    $key_bc92 = { ef fd [2] cb f3 [2] e0 df [2] ce fd [2] da e6 [2] d5 fc [2] cb e1 [2] c9 e0 [2] d2 e6 [2] ce e1 [2] d2 ce }

  condition:
    any of them
}