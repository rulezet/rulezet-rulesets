rule TTP_XOR_QUAD_CurrentVersionRun_58f8 {
  strings:
    $key_58f8 = { 0b 97 [2] 2f 99 [2] 04 b5 [2] 2a 97 [2] 3e 8c [2] 31 96 [2] 2f 8b [2] 2d 8a [2] 36 8c [2] 2a 8b [2] 36 a4 }

  condition:
    any of them
}