rule TTP_XOR_QUAD_CurrentVersionRun_7cca {
  strings:
    $key_7cca = { 2f a5 [2] 0b ab [2] 20 87 [2] 0e a5 [2] 1a be [2] 15 a4 [2] 0b b9 [2] 09 b8 [2] 12 be [2] 0e b9 [2] 12 96 }

  condition:
    any of them
}