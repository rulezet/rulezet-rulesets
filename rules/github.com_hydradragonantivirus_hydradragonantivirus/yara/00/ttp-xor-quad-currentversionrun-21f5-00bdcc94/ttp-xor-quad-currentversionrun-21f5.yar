rule TTP_XOR_QUAD_CurrentVersionRun_21f5 {
  strings:
    $key_21f5 = { 72 9a [2] 56 94 [2] 7d b8 [2] 53 9a [2] 47 81 [2] 48 9b [2] 56 86 [2] 54 87 [2] 4f 81 [2] 53 86 [2] 4f a9 }

  condition:
    any of them
}