rule TTP_XOR_QUAD_CurrentVersionRun_5ce5 {
  strings:
    $key_5ce5 = { 0f 8a [2] 2b 84 [2] 00 a8 [2] 2e 8a [2] 3a 91 [2] 35 8b [2] 2b 96 [2] 29 97 [2] 32 91 [2] 2e 96 [2] 32 b9 }

  condition:
    any of them
}