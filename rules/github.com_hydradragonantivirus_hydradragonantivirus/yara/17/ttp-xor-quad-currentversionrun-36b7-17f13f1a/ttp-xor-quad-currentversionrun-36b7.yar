rule TTP_XOR_QUAD_CurrentVersionRun_36b7 {
  strings:
    $key_36b7 = { 65 d8 [2] 41 d6 [2] 6a fa [2] 44 d8 [2] 50 c3 [2] 5f d9 [2] 41 c4 [2] 43 c5 [2] 58 c3 [2] 44 c4 [2] 58 eb }

  condition:
    any of them
}