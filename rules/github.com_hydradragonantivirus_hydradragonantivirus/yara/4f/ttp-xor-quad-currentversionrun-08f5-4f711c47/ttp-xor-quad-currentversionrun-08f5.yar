rule TTP_XOR_QUAD_CurrentVersionRun_08f5 {
  strings:
    $key_08f5 = { 5b 9a [2] 7f 94 [2] 54 b8 [2] 7a 9a [2] 6e 81 [2] 61 9b [2] 7f 86 [2] 7d 87 [2] 66 81 [2] 7a 86 [2] 66 a9 }

  condition:
    any of them
}