rule TTP_XOR_QUAD_CurrentVersionRun_6446 {
  strings:
    $key_6446 = { 37 29 [2] 13 27 [2] 38 0b [2] 16 29 [2] 02 32 [2] 0d 28 [2] 13 35 [2] 11 34 [2] 0a 32 [2] 16 35 [2] 0a 1a }

  condition:
    any of them
}