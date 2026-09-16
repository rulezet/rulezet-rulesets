rule TTP_XOR_QUAD_CurrentVersionRun_46f5 {
  strings:
    $key_46f5 = { 15 9a [2] 31 94 [2] 1a b8 [2] 34 9a [2] 20 81 [2] 2f 9b [2] 31 86 [2] 33 87 [2] 28 81 [2] 34 86 [2] 28 a9 }

  condition:
    any of them
}