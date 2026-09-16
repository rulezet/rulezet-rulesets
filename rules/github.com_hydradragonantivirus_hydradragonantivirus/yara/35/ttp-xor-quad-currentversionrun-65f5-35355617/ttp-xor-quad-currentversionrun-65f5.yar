rule TTP_XOR_QUAD_CurrentVersionRun_65f5 {
  strings:
    $key_65f5 = { 36 9a [2] 12 94 [2] 39 b8 [2] 17 9a [2] 03 81 [2] 0c 9b [2] 12 86 [2] 10 87 [2] 0b 81 [2] 17 86 [2] 0b a9 }

  condition:
    any of them
}