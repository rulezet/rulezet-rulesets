rule TTP_XOR_QUAD_CurrentVersionRun_5c1c {
  strings:
    $key_5c1c = { 0f 73 [2] 2b 7d [2] 00 51 [2] 2e 73 [2] 3a 68 [2] 35 72 [2] 2b 6f [2] 29 6e [2] 32 68 [2] 2e 6f [2] 32 40 }

  condition:
    any of them
}