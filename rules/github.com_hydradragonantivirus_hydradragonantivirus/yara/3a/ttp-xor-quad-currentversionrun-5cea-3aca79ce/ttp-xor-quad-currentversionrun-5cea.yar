rule TTP_XOR_QUAD_CurrentVersionRun_5cea {
  strings:
    $key_5cea = { 0f 85 [2] 2b 8b [2] 00 a7 [2] 2e 85 [2] 3a 9e [2] 35 84 [2] 2b 99 [2] 29 98 [2] 32 9e [2] 2e 99 [2] 32 b6 }

  condition:
    any of them
}