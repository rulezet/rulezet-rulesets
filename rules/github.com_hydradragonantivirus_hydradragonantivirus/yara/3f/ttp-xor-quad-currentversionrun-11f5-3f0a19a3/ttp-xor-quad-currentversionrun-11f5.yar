rule TTP_XOR_QUAD_CurrentVersionRun_11f5 {
  strings:
    $key_11f5 = { 42 9a [2] 66 94 [2] 4d b8 [2] 63 9a [2] 77 81 [2] 78 9b [2] 66 86 [2] 64 87 [2] 7f 81 [2] 63 86 [2] 7f a9 }

  condition:
    any of them
}