rule TTP_XOR_QUAD_CurrentVersionRun_7ff5 {
  strings:
    $key_7ff5 = { 2c 9a [2] 08 94 [2] 23 b8 [2] 0d 9a [2] 19 81 [2] 16 9b [2] 08 86 [2] 0a 87 [2] 11 81 [2] 0d 86 [2] 11 a9 }

  condition:
    any of them
}