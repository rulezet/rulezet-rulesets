rule TTP_XOR_QUAD_CurrentVersionRun_5c7a {
  strings:
    $key_5c7a = { 0f 15 [2] 2b 1b [2] 00 37 [2] 2e 15 [2] 3a 0e [2] 35 14 [2] 2b 09 [2] 29 08 [2] 32 0e [2] 2e 09 [2] 32 26 }

  condition:
    any of them
}