rule TTP_XOR_QUAD_CurrentVersionRun_a3b7 {
  strings:
    $key_a3b7 = { f0 d8 [2] d4 d6 [2] ff fa [2] d1 d8 [2] c5 c3 [2] ca d9 [2] d4 c4 [2] d6 c5 [2] cd c3 [2] d1 c4 [2] cd eb }

  condition:
    any of them
}