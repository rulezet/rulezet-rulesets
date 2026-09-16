rule TTP_XOR_QUAD_CurrentVersionRun_e2b7 {
  strings:
    $key_e2b7 = { b1 d8 [2] 95 d6 [2] be fa [2] 90 d8 [2] 84 c3 [2] 8b d9 [2] 95 c4 [2] 97 c5 [2] 8c c3 [2] 90 c4 [2] 8c eb }

  condition:
    any of them
}