rule TTP_XOR_QUAD_CurrentVersionRun_5c1a {
  strings:
    $key_5c1a = { 0f 75 [2] 2b 7b [2] 00 57 [2] 2e 75 [2] 3a 6e [2] 35 74 [2] 2b 69 [2] 29 68 [2] 32 6e [2] 2e 69 [2] 32 46 }

  condition:
    any of them
}