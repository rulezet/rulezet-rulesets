rule TTP_XOR_QUAD_CurrentVersionRun_37f5 {
  strings:
    $key_37f5 = { 64 9a [2] 40 94 [2] 6b b8 [2] 45 9a [2] 51 81 [2] 5e 9b [2] 40 86 [2] 42 87 [2] 59 81 [2] 45 86 [2] 59 a9 }

  condition:
    any of them
}