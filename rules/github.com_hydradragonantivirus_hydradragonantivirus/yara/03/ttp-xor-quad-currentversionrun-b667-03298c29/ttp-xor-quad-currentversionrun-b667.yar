rule TTP_XOR_QUAD_CurrentVersionRun_b667 {
  strings:
    $key_b667 = { e5 08 [2] c1 06 [2] ea 2a [2] c4 08 [2] d0 13 [2] df 09 [2] c1 14 [2] c3 15 [2] d8 13 [2] c4 14 [2] d8 3b }

  condition:
    any of them
}