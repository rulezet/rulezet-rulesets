rule TTP_XOR_QUAD_CurrentVersionRun_58e4 {
  strings:
    $key_58e4 = { 0b 8b [2] 2f 85 [2] 04 a9 [2] 2a 8b [2] 3e 90 [2] 31 8a [2] 2f 97 [2] 2d 96 [2] 36 90 [2] 2a 97 [2] 36 b8 }

  condition:
    any of them
}