rule TTP_XOR_QUAD_CurrentVersionRun_ebf5 {
  strings:
    $key_ebf5 = { b8 9a [2] 9c 94 [2] b7 b8 [2] 99 9a [2] 8d 81 [2] 82 9b [2] 9c 86 [2] 9e 87 [2] 85 81 [2] 99 86 [2] 85 a9 }

  condition:
    any of them
}