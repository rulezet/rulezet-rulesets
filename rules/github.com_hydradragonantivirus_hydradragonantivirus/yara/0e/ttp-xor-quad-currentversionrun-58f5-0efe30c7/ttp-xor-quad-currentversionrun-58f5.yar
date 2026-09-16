rule TTP_XOR_QUAD_CurrentVersionRun_58f5 {
  strings:
    $key_58f5 = { 0b 9a [2] 2f 94 [2] 04 b8 [2] 2a 9a [2] 3e 81 [2] 31 9b [2] 2f 86 [2] 2d 87 [2] 36 81 [2] 2a 86 [2] 36 a9 }

  condition:
    any of them
}