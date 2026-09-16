rule TTP_XOR_QUAD_CurrentVersionRun_51c6 {
  strings:
    $key_51c6 = { 02 a9 [2] 26 a7 [2] 0d 8b [2] 23 a9 [2] 37 b2 [2] 38 a8 [2] 26 b5 [2] 24 b4 [2] 3f b2 [2] 23 b5 [2] 3f 9a }

  condition:
    any of them
}