rule TTP_XOR_QUAD_CurrentVersionRun_5fc6 {
  strings:
    $key_5fc6 = { 0c a9 [2] 28 a7 [2] 03 8b [2] 2d a9 [2] 39 b2 [2] 36 a8 [2] 28 b5 [2] 2a b4 [2] 31 b2 [2] 2d b5 [2] 31 9a }

  condition:
    any of them
}