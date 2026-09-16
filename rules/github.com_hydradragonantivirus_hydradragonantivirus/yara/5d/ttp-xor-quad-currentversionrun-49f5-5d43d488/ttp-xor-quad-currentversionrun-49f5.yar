rule TTP_XOR_QUAD_CurrentVersionRun_49f5 {
  strings:
    $key_49f5 = { 1a 9a [2] 3e 94 [2] 15 b8 [2] 3b 9a [2] 2f 81 [2] 20 9b [2] 3e 86 [2] 3c 87 [2] 27 81 [2] 3b 86 [2] 27 a9 }

  condition:
    any of them
}