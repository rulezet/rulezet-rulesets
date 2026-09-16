rule TTP_XOR_QUAD_CurrentVersionRun_18f5 {
  strings:
    $key_18f5 = { 4b 9a [2] 6f 94 [2] 44 b8 [2] 6a 9a [2] 7e 81 [2] 71 9b [2] 6f 86 [2] 6d 87 [2] 76 81 [2] 6a 86 [2] 76 a9 }

  condition:
    any of them
}