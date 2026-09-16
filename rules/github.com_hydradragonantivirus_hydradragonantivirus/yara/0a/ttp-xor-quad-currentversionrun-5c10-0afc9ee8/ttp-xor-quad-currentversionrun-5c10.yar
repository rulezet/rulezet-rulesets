rule TTP_XOR_QUAD_CurrentVersionRun_5c10 {
  strings:
    $key_5c10 = { 0f 7f [2] 2b 71 [2] 00 5d [2] 2e 7f [2] 3a 64 [2] 35 7e [2] 2b 63 [2] 29 62 [2] 32 64 [2] 2e 63 [2] 32 4c }

  condition:
    any of them
}