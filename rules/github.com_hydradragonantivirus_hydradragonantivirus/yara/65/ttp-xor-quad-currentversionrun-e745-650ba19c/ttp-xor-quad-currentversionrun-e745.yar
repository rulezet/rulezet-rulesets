rule TTP_XOR_QUAD_CurrentVersionRun_e745 {
  strings:
    $key_e745 = { b4 2a [2] 90 24 [2] bb 08 [2] 95 2a [2] 81 31 [2] 8e 2b [2] 90 36 [2] 92 37 [2] 89 31 [2] 95 36 [2] 89 19 }

  condition:
    any of them
}