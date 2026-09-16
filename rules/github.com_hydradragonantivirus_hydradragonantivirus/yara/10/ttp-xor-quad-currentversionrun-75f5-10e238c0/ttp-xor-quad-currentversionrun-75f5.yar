rule TTP_XOR_QUAD_CurrentVersionRun_75f5 {
  strings:
    $key_75f5 = { 26 9a [2] 02 94 [2] 29 b8 [2] 07 9a [2] 13 81 [2] 1c 9b [2] 02 86 [2] 00 87 [2] 1b 81 [2] 07 86 [2] 1b a9 }

  condition:
    any of them
}