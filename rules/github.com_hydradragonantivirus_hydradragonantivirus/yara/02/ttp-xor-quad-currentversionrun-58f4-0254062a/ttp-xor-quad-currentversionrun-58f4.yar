rule TTP_XOR_QUAD_CurrentVersionRun_58f4 {
  strings:
    $key_58f4 = { 0b 9b [2] 2f 95 [2] 04 b9 [2] 2a 9b [2] 3e 80 [2] 31 9a [2] 2f 87 [2] 2d 86 [2] 36 80 [2] 2a 87 [2] 36 a8 }

  condition:
    any of them
}