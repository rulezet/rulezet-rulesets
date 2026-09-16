rule TTP_XOR_QUAD_CurrentVersionRun_bfb7 {
  strings:
    $key_bfb7 = { ec d8 [2] c8 d6 [2] e3 fa [2] cd d8 [2] d9 c3 [2] d6 d9 [2] c8 c4 [2] ca c5 [2] d1 c3 [2] cd c4 [2] d1 eb }

  condition:
    any of them
}