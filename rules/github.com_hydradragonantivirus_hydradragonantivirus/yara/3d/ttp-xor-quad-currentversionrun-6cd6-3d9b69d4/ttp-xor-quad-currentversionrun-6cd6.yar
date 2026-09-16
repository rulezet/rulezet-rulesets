rule TTP_XOR_QUAD_CurrentVersionRun_6cd6 {
  strings:
    $key_6cd6 = { 3f b9 [2] 1b b7 [2] 30 9b [2] 1e b9 [2] 0a a2 [2] 05 b8 [2] 1b a5 [2] 19 a4 [2] 02 a2 [2] 1e a5 [2] 02 8a }

  condition:
    any of them
}