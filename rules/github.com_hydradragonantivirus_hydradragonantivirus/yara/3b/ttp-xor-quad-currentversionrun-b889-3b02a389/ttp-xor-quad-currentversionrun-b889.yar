rule TTP_XOR_QUAD_CurrentVersionRun_b889 {
  strings:
    $key_b889 = { eb e6 [2] cf e8 [2] e4 c4 [2] ca e6 [2] de fd [2] d1 e7 [2] cf fa [2] cd fb [2] d6 fd [2] ca fa [2] d6 d5 }

  condition:
    any of them
}