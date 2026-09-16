rule TTP_XOR_QUAD_CurrentVersionRun_66b7 {
  strings:
    $key_66b7 = { 35 d8 [2] 11 d6 [2] 3a fa [2] 14 d8 [2] 00 c3 [2] 0f d9 [2] 11 c4 [2] 13 c5 [2] 08 c3 [2] 14 c4 [2] 08 eb }

  condition:
    any of them
}