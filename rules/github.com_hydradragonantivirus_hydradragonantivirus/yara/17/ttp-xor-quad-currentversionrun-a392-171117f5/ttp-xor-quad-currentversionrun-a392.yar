rule TTP_XOR_QUAD_CurrentVersionRun_a392 {
  strings:
    $key_a392 = { f0 fd [2] d4 f3 [2] ff df [2] d1 fd [2] c5 e6 [2] ca fc [2] d4 e1 [2] d6 e0 [2] cd e6 [2] d1 e1 [2] cd ce }

  condition:
    any of them
}