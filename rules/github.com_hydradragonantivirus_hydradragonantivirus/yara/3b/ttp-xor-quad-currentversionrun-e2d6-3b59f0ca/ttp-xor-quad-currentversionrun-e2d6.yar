rule TTP_XOR_QUAD_CurrentVersionRun_e2d6 {
  strings:
    $key_e2d6 = { b1 b9 [2] 95 b7 [2] be 9b [2] 90 b9 [2] 84 a2 [2] 8b b8 [2] 95 a5 [2] 97 a4 [2] 8c a2 [2] 90 a5 [2] 8c 8a }

  condition:
    any of them
}