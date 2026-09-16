rule TTP_XOR_QUAD_CurrentVersionRun_e4f5 {
  strings:
    $key_e4f5 = { b7 9a [2] 93 94 [2] b8 b8 [2] 96 9a [2] 82 81 [2] 8d 9b [2] 93 86 [2] 91 87 [2] 8a 81 [2] 96 86 [2] 8a a9 }

  condition:
    any of them
}