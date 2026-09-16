rule TTP_XOR_QUAD_CurrentVersionRun_7cf4 {
  strings:
    $key_7cf4 = { 2f 9b [2] 0b 95 [2] 20 b9 [2] 0e 9b [2] 1a 80 [2] 15 9a [2] 0b 87 [2] 09 86 [2] 12 80 [2] 0e 87 [2] 12 a8 }

  condition:
    any of them
}