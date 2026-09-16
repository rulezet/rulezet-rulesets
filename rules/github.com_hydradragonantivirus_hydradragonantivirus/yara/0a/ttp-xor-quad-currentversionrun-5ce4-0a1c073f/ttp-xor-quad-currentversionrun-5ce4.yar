rule TTP_XOR_QUAD_CurrentVersionRun_5ce4 {
  strings:
    $key_5ce4 = { 0f 8b [2] 2b 85 [2] 00 a9 [2] 2e 8b [2] 3a 90 [2] 35 8a [2] 2b 97 [2] 29 96 [2] 32 90 [2] 2e 97 [2] 32 b8 }

  condition:
    any of them
}