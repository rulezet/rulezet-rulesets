rule TTP_XOR_QUAD_CurrentVersionRun_7f16 {
  strings:
    $key_7f16 = { 2c 79 [2] 08 77 [2] 23 5b [2] 0d 79 [2] 19 62 [2] 16 78 [2] 08 65 [2] 0a 64 [2] 11 62 [2] 0d 65 [2] 11 4a }

  condition:
    any of them
}