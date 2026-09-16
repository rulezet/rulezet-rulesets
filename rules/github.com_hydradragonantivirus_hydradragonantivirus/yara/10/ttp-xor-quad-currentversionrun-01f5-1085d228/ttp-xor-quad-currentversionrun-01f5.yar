rule TTP_XOR_QUAD_CurrentVersionRun_01f5 {
  strings:
    $key_01f5 = { 52 9a [2] 76 94 [2] 5d b8 [2] 73 9a [2] 67 81 [2] 68 9b [2] 76 86 [2] 74 87 [2] 6f 81 [2] 73 86 [2] 6f a9 }

  condition:
    any of them
}