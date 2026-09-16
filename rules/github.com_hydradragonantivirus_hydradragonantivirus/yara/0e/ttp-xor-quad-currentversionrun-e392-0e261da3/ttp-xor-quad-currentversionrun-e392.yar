rule TTP_XOR_QUAD_CurrentVersionRun_e392 {
  strings:
    $key_e392 = { b0 fd [2] 94 f3 [2] bf df [2] 91 fd [2] 85 e6 [2] 8a fc [2] 94 e1 [2] 96 e0 [2] 8d e6 [2] 91 e1 [2] 8d ce }

  condition:
    any of them
}