rule TTP_XOR_QUAD_CurrentVersionRun_5df5 {
  strings:
    $key_5df5 = { 0e 9a [2] 2a 94 [2] 01 b8 [2] 2f 9a [2] 3b 81 [2] 34 9b [2] 2a 86 [2] 28 87 [2] 33 81 [2] 2f 86 [2] 33 a9 }

  condition:
    any of them
}