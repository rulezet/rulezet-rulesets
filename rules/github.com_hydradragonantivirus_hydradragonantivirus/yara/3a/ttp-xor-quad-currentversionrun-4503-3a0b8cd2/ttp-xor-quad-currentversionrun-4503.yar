rule TTP_XOR_QUAD_CurrentVersionRun_4503 {
  strings:
    $key_4503 = { 16 6c [2] 32 62 [2] 19 4e [2] 37 6c [2] 23 77 [2] 2c 6d [2] 32 70 [2] 30 71 [2] 2b 77 [2] 37 70 [2] 2b 5f }

  condition:
    any of them
}