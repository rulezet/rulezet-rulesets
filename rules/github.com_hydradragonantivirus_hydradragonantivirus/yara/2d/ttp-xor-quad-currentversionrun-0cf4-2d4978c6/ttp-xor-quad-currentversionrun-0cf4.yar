rule TTP_XOR_QUAD_CurrentVersionRun_0cf4 {
  strings:
    $key_0cf4 = { 5f 9b [2] 7b 95 [2] 50 b9 [2] 7e 9b [2] 6a 80 [2] 65 9a [2] 7b 87 [2] 79 86 [2] 62 80 [2] 7e 87 [2] 62 a8 }

  condition:
    any of them
}