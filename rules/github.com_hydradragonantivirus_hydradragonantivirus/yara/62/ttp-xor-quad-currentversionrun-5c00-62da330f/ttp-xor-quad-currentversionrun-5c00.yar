rule TTP_XOR_QUAD_CurrentVersionRun_5c00 {
  strings:
    $key_5c00 = { 0f 6f [2] 2b 61 [2] 00 4d [2] 2e 6f [2] 3a 74 [2] 35 6e [2] 2b 73 [2] 29 72 [2] 32 74 [2] 2e 73 [2] 32 5c }

  condition:
    any of them
}