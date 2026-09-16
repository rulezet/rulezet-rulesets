rule TTP_XOR_QUAD_CurrentVersionRun_7df5 {
  strings:
    $key_7df5 = { 2e 9a [2] 0a 94 [2] 21 b8 [2] 0f 9a [2] 1b 81 [2] 14 9b [2] 0a 86 [2] 08 87 [2] 13 81 [2] 0f 86 [2] 13 a9 }

  condition:
    any of them
}