rule TTP_XOR_QUAD_CurrentVersionRun_5c2c {
  strings:
    $key_5c2c = { 0f 43 [2] 2b 4d [2] 00 61 [2] 2e 43 [2] 3a 58 [2] 35 42 [2] 2b 5f [2] 29 5e [2] 32 58 [2] 2e 5f [2] 32 70 }

  condition:
    any of them
}