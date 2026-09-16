rule TTP_XOR_QUAD_CurrentVersionRun_c793 {
  strings:
    $key_c793 = { 94 fc [2] b0 f2 [2] 9b de [2] b5 fc [2] a1 e7 [2] ae fd [2] b0 e0 [2] b2 e1 [2] a9 e7 [2] b5 e0 [2] a9 cf }

  condition:
    any of them
}