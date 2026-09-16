rule TTP_XOR_QUAD_CurrentVersionRun_6cca {
  strings:
    $key_6cca = { 3f a5 [2] 1b ab [2] 30 87 [2] 1e a5 [2] 0a be [2] 05 a4 [2] 1b b9 [2] 19 b8 [2] 02 be [2] 1e b9 [2] 02 96 }

  condition:
    any of them
}