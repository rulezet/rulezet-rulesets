rule TTP_XOR_QUAD_CurrentVersionRun_ebb6 {
  strings:
    $key_ebb6 = { b8 d9 [2] 9c d7 [2] b7 fb [2] 99 d9 [2] 8d c2 [2] 82 d8 [2] 9c c5 [2] 9e c4 [2] 85 c2 [2] 99 c5 [2] 85 ea }

  condition:
    any of them
}