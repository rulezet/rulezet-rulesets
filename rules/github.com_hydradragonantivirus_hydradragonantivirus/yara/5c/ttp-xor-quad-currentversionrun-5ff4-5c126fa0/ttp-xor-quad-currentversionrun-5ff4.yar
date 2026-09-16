rule TTP_XOR_QUAD_CurrentVersionRun_5ff4 {
  strings:
    $key_5ff4 = { 0c 9b [2] 28 95 [2] 03 b9 [2] 2d 9b [2] 39 80 [2] 36 9a [2] 28 87 [2] 2a 86 [2] 31 80 [2] 2d 87 [2] 31 a8 }

  condition:
    any of them
}