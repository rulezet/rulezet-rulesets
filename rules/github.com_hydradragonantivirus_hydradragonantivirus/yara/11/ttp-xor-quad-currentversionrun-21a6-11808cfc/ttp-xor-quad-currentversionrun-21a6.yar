rule TTP_XOR_QUAD_CurrentVersionRun_21a6 {
  strings:
    $key_21a6 = { 72 c9 [2] 56 c7 [2] 7d eb [2] 53 c9 [2] 47 d2 [2] 48 c8 [2] 56 d5 [2] 54 d4 [2] 4f d2 [2] 53 d5 [2] 4f fa }

  condition:
    any of them
}