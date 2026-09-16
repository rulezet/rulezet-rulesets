rule TTP_XOR_QUAD_CurrentVersionRun_5cf4 {
  strings:
    $key_5cf4 = { 0f 9b [2] 2b 95 [2] 00 b9 [2] 2e 9b [2] 3a 80 [2] 35 9a [2] 2b 87 [2] 29 86 [2] 32 80 [2] 2e 87 [2] 32 a8 }

  condition:
    any of them
}