rule TTP_XOR_QUAD_CurrentVersionRun_5c45 {
  strings:
    $key_5c45 = { 0f 2a [2] 2b 24 [2] 00 08 [2] 2e 2a [2] 3a 31 [2] 35 2b [2] 2b 36 [2] 29 37 [2] 32 31 [2] 2e 36 [2] 32 19 }

  condition:
    any of them
}