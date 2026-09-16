rule TTP_XOR_QUAD_CurrentVersionRun_ecd6 {
  strings:
    $key_ecd6 = { bf b9 [2] 9b b7 [2] b0 9b [2] 9e b9 [2] 8a a2 [2] 85 b8 [2] 9b a5 [2] 99 a4 [2] 82 a2 [2] 9e a5 [2] 82 8a }

  condition:
    any of them
}