rule TTP_XOR_QUAD_CurrentVersionRun_26b7 {
  strings:
    $key_26b7 = { 75 d8 [2] 51 d6 [2] 7a fa [2] 54 d8 [2] 40 c3 [2] 4f d9 [2] 51 c4 [2] 53 c5 [2] 48 c3 [2] 54 c4 [2] 48 eb }

  condition:
    any of them
}