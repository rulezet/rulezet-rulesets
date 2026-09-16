rule TTP_XOR_QUAD_CurrentVersionRun_56f5 {
  strings:
    $key_56f5 = { 05 9a [2] 21 94 [2] 0a b8 [2] 24 9a [2] 30 81 [2] 3f 9b [2] 21 86 [2] 23 87 [2] 38 81 [2] 24 86 [2] 38 a9 }

  condition:
    any of them
}