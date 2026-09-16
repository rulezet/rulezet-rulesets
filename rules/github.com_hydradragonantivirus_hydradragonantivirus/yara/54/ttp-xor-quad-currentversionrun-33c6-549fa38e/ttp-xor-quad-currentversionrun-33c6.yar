rule TTP_XOR_QUAD_CurrentVersionRun_33c6 {
  strings:
    $key_33c6 = { 60 a9 [2] 44 a7 [2] 6f 8b [2] 41 a9 [2] 55 b2 [2] 5a a8 [2] 44 b5 [2] 46 b4 [2] 5d b2 [2] 41 b5 [2] 5d 9a }

  condition:
    any of them
}