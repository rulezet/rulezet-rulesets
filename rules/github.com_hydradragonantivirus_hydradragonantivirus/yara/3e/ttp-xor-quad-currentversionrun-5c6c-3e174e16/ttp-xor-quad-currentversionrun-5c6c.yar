rule TTP_XOR_QUAD_CurrentVersionRun_5c6c {
  strings:
    $key_5c6c = { 0f 03 [2] 2b 0d [2] 00 21 [2] 2e 03 [2] 3a 18 [2] 35 02 [2] 2b 1f [2] 29 1e [2] 32 18 [2] 2e 1f [2] 32 30 }

  condition:
    any of them
}