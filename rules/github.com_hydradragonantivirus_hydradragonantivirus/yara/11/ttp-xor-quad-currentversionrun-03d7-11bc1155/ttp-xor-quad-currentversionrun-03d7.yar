rule TTP_XOR_QUAD_CurrentVersionRun_03d7 {
  strings:
    $key_03d7 = { 50 b8 [2] 74 b6 [2] 5f 9a [2] 71 b8 [2] 65 a3 [2] 6a b9 [2] 74 a4 [2] 76 a5 [2] 6d a3 [2] 71 a4 [2] 6d 8b }

  condition:
    any of them
}