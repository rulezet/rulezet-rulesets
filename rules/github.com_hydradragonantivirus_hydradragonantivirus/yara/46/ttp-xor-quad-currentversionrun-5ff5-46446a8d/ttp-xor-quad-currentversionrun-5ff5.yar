rule TTP_XOR_QUAD_CurrentVersionRun_5ff5 {
  strings:
    $key_5ff5 = { 0c 9a [2] 28 94 [2] 03 b8 [2] 2d 9a [2] 39 81 [2] 36 9b [2] 28 86 [2] 2a 87 [2] 31 81 [2] 2d 86 [2] 31 a9 }

  condition:
    any of them
}