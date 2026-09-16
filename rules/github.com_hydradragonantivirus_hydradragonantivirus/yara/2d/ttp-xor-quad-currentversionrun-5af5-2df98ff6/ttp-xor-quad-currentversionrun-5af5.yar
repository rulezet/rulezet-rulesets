rule TTP_XOR_QUAD_CurrentVersionRun_5af5 {
  strings:
    $key_5af5 = { 09 9a [2] 2d 94 [2] 06 b8 [2] 28 9a [2] 3c 81 [2] 33 9b [2] 2d 86 [2] 2f 87 [2] 34 81 [2] 28 86 [2] 34 a9 }

  condition:
    any of them
}