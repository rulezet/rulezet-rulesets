rule TTP_XOR_QUAD_CurrentVersionRun_7016 {
  strings:
    $key_7016 = { 23 79 [2] 07 77 [2] 2c 5b [2] 02 79 [2] 16 62 [2] 19 78 [2] 07 65 [2] 05 64 [2] 1e 62 [2] 02 65 [2] 1e 4a }

  condition:
    any of them
}