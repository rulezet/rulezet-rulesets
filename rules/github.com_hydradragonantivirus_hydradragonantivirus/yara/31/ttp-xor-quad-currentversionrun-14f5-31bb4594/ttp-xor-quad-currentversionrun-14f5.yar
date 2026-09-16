rule TTP_XOR_QUAD_CurrentVersionRun_14f5 {
  strings:
    $key_14f5 = { 47 9a [2] 63 94 [2] 48 b8 [2] 66 9a [2] 72 81 [2] 7d 9b [2] 63 86 [2] 61 87 [2] 7a 81 [2] 66 86 [2] 7a a9 }

  condition:
    any of them
}