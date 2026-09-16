rule TTP_XOR_QUAD_CurrentVersionRun_d8b7 {
  strings:
    $key_d8b7 = { 8b d8 [2] af d6 [2] 84 fa [2] aa d8 [2] be c3 [2] b1 d9 [2] af c4 [2] ad c5 [2] b6 c3 [2] aa c4 [2] b6 eb }

  condition:
    any of them
}