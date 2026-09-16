rule TTP_XOR_QUAD_CurrentVersionRun_ecd7 {
  strings:
    $key_ecd7 = { bf b8 [2] 9b b6 [2] b0 9a [2] 9e b8 [2] 8a a3 [2] 85 b9 [2] 9b a4 [2] 99 a5 [2] 82 a3 [2] 9e a4 [2] 82 8b }

  condition:
    any of them
}