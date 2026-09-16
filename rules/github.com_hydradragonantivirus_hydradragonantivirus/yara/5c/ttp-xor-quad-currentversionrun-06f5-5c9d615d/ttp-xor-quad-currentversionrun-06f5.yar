rule TTP_XOR_QUAD_CurrentVersionRun_06f5 {
  strings:
    $key_06f5 = { 55 9a [2] 71 94 [2] 5a b8 [2] 74 9a [2] 60 81 [2] 6f 9b [2] 71 86 [2] 73 87 [2] 68 81 [2] 74 86 [2] 68 a9 }

  condition:
    any of them
}