rule TTP_XOR_QUAD_CurrentVersionRun_16f5 {
  strings:
    $key_16f5 = { 45 9a [2] 61 94 [2] 4a b8 [2] 64 9a [2] 70 81 [2] 7f 9b [2] 61 86 [2] 63 87 [2] 78 81 [2] 64 86 [2] 78 a9 }

  condition:
    any of them
}