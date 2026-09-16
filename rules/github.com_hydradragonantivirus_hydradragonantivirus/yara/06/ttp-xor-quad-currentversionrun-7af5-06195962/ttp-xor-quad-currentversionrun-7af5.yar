rule TTP_XOR_QUAD_CurrentVersionRun_7af5 {
  strings:
    $key_7af5 = { 29 9a [2] 0d 94 [2] 26 b8 [2] 08 9a [2] 1c 81 [2] 13 9b [2] 0d 86 [2] 0f 87 [2] 14 81 [2] 08 86 [2] 14 a9 }

  condition:
    any of them
}