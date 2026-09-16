rule TTP_XOR_QUAD_CurrentVersionRun_4216 {
  strings:
    $key_4216 = { 11 79 [2] 35 77 [2] 1e 5b [2] 30 79 [2] 24 62 [2] 2b 78 [2] 35 65 [2] 37 64 [2] 2c 62 [2] 30 65 [2] 2c 4a }

  condition:
    any of them
}