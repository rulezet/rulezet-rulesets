rule TTP_XOR_QUAD_CurrentVersionRun_46e4 {
  strings:
    $key_46e4 = { 15 8b [2] 31 85 [2] 1a a9 [2] 34 8b [2] 20 90 [2] 2f 8a [2] 31 97 [2] 33 96 [2] 28 90 [2] 34 97 [2] 28 b8 }

  condition:
    any of them
}