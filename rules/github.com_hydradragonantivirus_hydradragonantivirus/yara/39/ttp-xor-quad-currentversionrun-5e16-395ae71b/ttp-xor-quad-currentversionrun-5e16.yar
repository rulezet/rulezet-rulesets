rule TTP_XOR_QUAD_CurrentVersionRun_5e16 {
  strings:
    $key_5e16 = { 0d 79 [2] 29 77 [2] 02 5b [2] 2c 79 [2] 38 62 [2] 37 78 [2] 29 65 [2] 2b 64 [2] 30 62 [2] 2c 65 [2] 30 4a }

  condition:
    any of them
}