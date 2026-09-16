rule TTP_XOR_QUAD_CurrentVersionRun_03d6 {
  strings:
    $key_03d6 = { 50 b9 [2] 74 b7 [2] 5f 9b [2] 71 b9 [2] 65 a2 [2] 6a b8 [2] 74 a5 [2] 76 a4 [2] 6d a2 [2] 71 a5 [2] 6d 8a }

  condition:
    any of them
}