rule TTP_XOR_QUAD_CurrentVersionRun_5ce8 {
  strings:
    $key_5ce8 = { 0f 87 [2] 2b 89 [2] 00 a5 [2] 2e 87 [2] 3a 9c [2] 35 86 [2] 2b 9b [2] 29 9a [2] 32 9c [2] 2e 9b [2] 32 b4 }

  condition:
    any of them
}