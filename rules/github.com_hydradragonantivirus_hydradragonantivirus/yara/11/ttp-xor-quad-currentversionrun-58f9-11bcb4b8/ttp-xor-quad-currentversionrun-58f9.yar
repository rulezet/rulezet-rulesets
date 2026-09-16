rule TTP_XOR_QUAD_CurrentVersionRun_58f9 {
  strings:
    $key_58f9 = { 0b 96 [2] 2f 98 [2] 04 b4 [2] 2a 96 [2] 3e 8d [2] 31 97 [2] 2f 8a [2] 2d 8b [2] 36 8d [2] 2a 8a [2] 36 a5 }

  condition:
    any of them
}