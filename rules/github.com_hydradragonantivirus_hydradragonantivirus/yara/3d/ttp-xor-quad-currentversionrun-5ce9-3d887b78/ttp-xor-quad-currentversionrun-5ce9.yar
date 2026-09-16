rule TTP_XOR_QUAD_CurrentVersionRun_5ce9 {
  strings:
    $key_5ce9 = { 0f 86 [2] 2b 88 [2] 00 a4 [2] 2e 86 [2] 3a 9d [2] 35 87 [2] 2b 9a [2] 29 9b [2] 32 9d [2] 2e 9a [2] 32 b5 }

  condition:
    any of them
}