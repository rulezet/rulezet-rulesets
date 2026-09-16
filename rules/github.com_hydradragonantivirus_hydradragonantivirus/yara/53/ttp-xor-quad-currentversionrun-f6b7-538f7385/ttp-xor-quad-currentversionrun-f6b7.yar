rule TTP_XOR_QUAD_CurrentVersionRun_f6b7 {
  strings:
    $key_f6b7 = { a5 d8 [2] 81 d6 [2] aa fa [2] 84 d8 [2] 90 c3 [2] 9f d9 [2] 81 c4 [2] 83 c5 [2] 98 c3 [2] 84 c4 [2] 98 eb }

  condition:
    any of them
}