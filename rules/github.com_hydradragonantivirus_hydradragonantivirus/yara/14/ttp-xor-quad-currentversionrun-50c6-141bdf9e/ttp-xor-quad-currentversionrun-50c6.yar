rule TTP_XOR_QUAD_CurrentVersionRun_50c6 {
  strings:
    $key_50c6 = { 03 a9 [2] 27 a7 [2] 0c 8b [2] 22 a9 [2] 36 b2 [2] 39 a8 [2] 27 b5 [2] 25 b4 [2] 3e b2 [2] 22 b5 [2] 3e 9a }

  condition:
    any of them
}