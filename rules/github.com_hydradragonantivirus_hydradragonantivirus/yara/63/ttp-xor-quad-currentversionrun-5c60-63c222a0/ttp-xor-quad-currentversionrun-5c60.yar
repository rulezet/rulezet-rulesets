rule TTP_XOR_QUAD_CurrentVersionRun_5c60 {
  strings:
    $key_5c60 = { 0f 0f [2] 2b 01 [2] 00 2d [2] 2e 0f [2] 3a 14 [2] 35 0e [2] 2b 13 [2] 29 12 [2] 32 14 [2] 2e 13 [2] 32 3c }

  condition:
    any of them
}