rule TTP_XOR_QUAD_CurrentVersionRun_e2d7 {
  strings:
    $key_e2d7 = { b1 b8 [2] 95 b6 [2] be 9a [2] 90 b8 [2] 84 a3 [2] 8b b9 [2] 95 a4 [2] 97 a5 [2] 8c a3 [2] 90 a4 [2] 8c 8b }

  condition:
    any of them
}