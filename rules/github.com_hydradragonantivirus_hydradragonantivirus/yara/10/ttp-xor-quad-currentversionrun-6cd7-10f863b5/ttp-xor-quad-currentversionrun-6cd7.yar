rule TTP_XOR_QUAD_CurrentVersionRun_6cd7 {
  strings:
    $key_6cd7 = { 3f b8 [2] 1b b6 [2] 30 9a [2] 1e b8 [2] 0a a3 [2] 05 b9 [2] 1b a4 [2] 19 a5 [2] 02 a3 [2] 1e a4 [2] 02 8b }

  condition:
    any of them
}