rule TTP_XOR_QUAD_CurrentVersionRun_01c7 {
  strings:
    $key_01c7 = { 52 a8 [2] 76 a6 [2] 5d 8a [2] 73 a8 [2] 67 b3 [2] 68 a9 [2] 76 b4 [2] 74 b5 [2] 6f b3 [2] 73 b4 [2] 6f 9b }

  condition:
    any of them
}