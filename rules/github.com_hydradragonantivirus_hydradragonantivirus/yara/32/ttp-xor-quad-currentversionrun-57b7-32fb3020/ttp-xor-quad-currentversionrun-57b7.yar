rule TTP_XOR_QUAD_CurrentVersionRun_57b7 {
  strings:
    $key_57b7 = { 04 d8 [2] 20 d6 [2] 0b fa [2] 25 d8 [2] 31 c3 [2] 3e d9 [2] 20 c4 [2] 22 c5 [2] 39 c3 [2] 25 c4 [2] 39 eb }

  condition:
    any of them
}