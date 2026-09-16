rule TTP_XOR_QUAD_CurrentVersionRun_5cca {
  strings:
    $key_5cca = { 0f a5 [2] 2b ab [2] 00 87 [2] 2e a5 [2] 3a be [2] 35 a4 [2] 2b b9 [2] 29 b8 [2] 32 be [2] 2e b9 [2] 32 96 }

  condition:
    any of them
}