rule TTP_XOR_QUAD_CurrentVersionRun_68f4 {
  strings:
    $key_68f4 = { 3b 9b [2] 1f 95 [2] 34 b9 [2] 1a 9b [2] 0e 80 [2] 01 9a [2] 1f 87 [2] 1d 86 [2] 06 80 [2] 1a 87 [2] 06 a8 }

  condition:
    any of them
}