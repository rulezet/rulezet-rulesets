rule TTP_XOR_QUAD_CurrentVersionRun_e9d6 {
  strings:
    $key_e9d6 = { ba b9 [2] 9e b7 [2] b5 9b [2] 9b b9 [2] 8f a2 [2] 80 b8 [2] 9e a5 [2] 9c a4 [2] 87 a2 [2] 9b a5 [2] 87 8a }

  condition:
    any of them
}