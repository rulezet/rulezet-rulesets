rule TTP_XOR_QUAD_CurrentVersionRun_5c4d {
  strings:
    $key_5c4d = { 0f 22 [2] 2b 2c [2] 00 00 [2] 2e 22 [2] 3a 39 [2] 35 23 [2] 2b 3e [2] 29 3f [2] 32 39 [2] 2e 3e [2] 32 11 }

  condition:
    any of them
}