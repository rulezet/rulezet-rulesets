rule TTP_XOR_QUAD_CurrentVersionRun_5cf9 {
  strings:
    $key_5cf9 = { 0f 96 [2] 2b 98 [2] 00 b4 [2] 2e 96 [2] 3a 8d [2] 35 97 [2] 2b 8a [2] 29 8b [2] 32 8d [2] 2e 8a [2] 32 a5 }

  condition:
    any of them
}