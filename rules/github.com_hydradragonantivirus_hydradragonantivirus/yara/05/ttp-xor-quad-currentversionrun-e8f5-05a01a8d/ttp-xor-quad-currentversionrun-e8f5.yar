rule TTP_XOR_QUAD_CurrentVersionRun_e8f5 {
  strings:
    $key_e8f5 = { bb 9a [2] 9f 94 [2] b4 b8 [2] 9a 9a [2] 8e 81 [2] 81 9b [2] 9f 86 [2] 9d 87 [2] 86 81 [2] 9a 86 [2] 86 a9 }

  condition:
    any of them
}