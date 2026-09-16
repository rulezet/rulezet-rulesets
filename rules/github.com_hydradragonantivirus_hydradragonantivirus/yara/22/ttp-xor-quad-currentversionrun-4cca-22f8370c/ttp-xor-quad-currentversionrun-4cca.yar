rule TTP_XOR_QUAD_CurrentVersionRun_4cca {
  strings:
    $key_4cca = { 1f a5 [2] 3b ab [2] 10 87 [2] 3e a5 [2] 2a be [2] 25 a4 [2] 3b b9 [2] 39 b8 [2] 22 be [2] 3e b9 [2] 22 96 }

  condition:
    any of them
}