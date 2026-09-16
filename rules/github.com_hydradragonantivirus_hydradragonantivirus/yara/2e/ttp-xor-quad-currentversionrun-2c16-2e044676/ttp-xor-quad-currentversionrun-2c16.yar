rule TTP_XOR_QUAD_CurrentVersionRun_2c16 {
  strings:
    $key_2c16 = { 7f 79 [2] 5b 77 [2] 70 5b [2] 5e 79 [2] 4a 62 [2] 45 78 [2] 5b 65 [2] 59 64 [2] 42 62 [2] 5e 65 [2] 42 4a }

  condition:
    any of them
}