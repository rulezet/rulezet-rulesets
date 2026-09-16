rule TTP_XOR_QUAD_CurrentVersionRun_5c7b {
  strings:
    $key_5c7b = { 0f 14 [2] 2b 1a [2] 00 36 [2] 2e 14 [2] 3a 0f [2] 35 15 [2] 2b 08 [2] 29 09 [2] 32 0f [2] 2e 08 [2] 32 27 }

  condition:
    any of them
}