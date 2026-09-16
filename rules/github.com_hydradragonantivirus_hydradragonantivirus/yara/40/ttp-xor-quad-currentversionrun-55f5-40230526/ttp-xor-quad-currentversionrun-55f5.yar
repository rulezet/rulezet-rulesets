rule TTP_XOR_QUAD_CurrentVersionRun_55f5 {
  strings:
    $key_55f5 = { 06 9a [2] 22 94 [2] 09 b8 [2] 27 9a [2] 33 81 [2] 3c 9b [2] 22 86 [2] 20 87 [2] 3b 81 [2] 27 86 [2] 3b a9 }

  condition:
    any of them
}