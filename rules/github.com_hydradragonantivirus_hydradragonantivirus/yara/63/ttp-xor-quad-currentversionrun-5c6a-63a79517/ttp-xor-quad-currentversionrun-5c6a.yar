rule TTP_XOR_QUAD_CurrentVersionRun_5c6a {
  strings:
    $key_5c6a = { 0f 05 [2] 2b 0b [2] 00 27 [2] 2e 05 [2] 3a 1e [2] 35 04 [2] 2b 19 [2] 29 18 [2] 32 1e [2] 2e 19 [2] 32 36 }

  condition:
    any of them
}