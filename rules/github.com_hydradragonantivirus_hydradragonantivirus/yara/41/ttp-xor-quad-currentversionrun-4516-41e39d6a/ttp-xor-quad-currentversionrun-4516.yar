rule TTP_XOR_QUAD_CurrentVersionRun_4516 {
  strings:
    $key_4516 = { 16 79 [2] 32 77 [2] 19 5b [2] 37 79 [2] 23 62 [2] 2c 78 [2] 32 65 [2] 30 64 [2] 2b 62 [2] 37 65 [2] 2b 4a }

  condition:
    any of them
}