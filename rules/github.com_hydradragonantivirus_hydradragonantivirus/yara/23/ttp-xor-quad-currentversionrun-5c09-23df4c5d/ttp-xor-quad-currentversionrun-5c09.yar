rule TTP_XOR_QUAD_CurrentVersionRun_5c09 {
  strings:
    $key_5c09 = { 0f 66 [2] 2b 68 [2] 00 44 [2] 2e 66 [2] 3a 7d [2] 35 67 [2] 2b 7a [2] 29 7b [2] 32 7d [2] 2e 7a [2] 32 55 }

  condition:
    any of them
}