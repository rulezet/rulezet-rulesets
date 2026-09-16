rule TTP_XOR_QUAD_CurrentVersionRun_ebb5 {
  strings:
    $key_ebb5 = { b8 da [2] 9c d4 [2] b7 f8 [2] 99 da [2] 8d c1 [2] 82 db [2] 9c c6 [2] 9e c7 [2] 85 c1 [2] 99 c6 [2] 85 e9 }

  condition:
    any of them
}