rule TTP_XOR_QUAD_CurrentVersionRun_e9d7 {
  strings:
    $key_e9d7 = { ba b8 [2] 9e b6 [2] b5 9a [2] 9b b8 [2] 8f a3 [2] 80 b9 [2] 9e a4 [2] 9c a5 [2] 87 a3 [2] 9b a4 [2] 87 8b }

  condition:
    any of them
}