rule TTP_XOR_QUAD_CurrentVersionRun_63c6 {
  strings:
    $key_63c6 = { 30 a9 [2] 14 a7 [2] 3f 8b [2] 11 a9 [2] 05 b2 [2] 0a a8 [2] 14 b5 [2] 16 b4 [2] 0d b2 [2] 11 b5 [2] 0d 9a }

  condition:
    any of them
}