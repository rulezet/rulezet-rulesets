rule TTP_XOR_QUAD_CurrentVersionRun_a092 {
  strings:
    $key_a092 = { f3 fd [2] d7 f3 [2] fc df [2] d2 fd [2] c6 e6 [2] c9 fc [2] d7 e1 [2] d5 e0 [2] ce e6 [2] d2 e1 [2] ce ce }

  condition:
    any of them
}