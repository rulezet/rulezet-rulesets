rule TTP_XOR_QUAD_CurrentVersionRun_5c68 {
  strings:
    $key_5c68 = { 0f 07 [2] 2b 09 [2] 00 25 [2] 2e 07 [2] 3a 1c [2] 35 06 [2] 2b 1b [2] 29 1a [2] 32 1c [2] 2e 1b [2] 32 34 }

  condition:
    any of them
}