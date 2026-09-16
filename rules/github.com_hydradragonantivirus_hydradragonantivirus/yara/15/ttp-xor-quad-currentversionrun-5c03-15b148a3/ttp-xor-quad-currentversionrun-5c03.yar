rule TTP_XOR_QUAD_CurrentVersionRun_5c03 {
  strings:
    $key_5c03 = { 0f 6c [2] 2b 62 [2] 00 4e [2] 2e 6c [2] 3a 77 [2] 35 6d [2] 2b 70 [2] 29 71 [2] 32 77 [2] 2e 70 [2] 32 5f }

  condition:
    any of them
}