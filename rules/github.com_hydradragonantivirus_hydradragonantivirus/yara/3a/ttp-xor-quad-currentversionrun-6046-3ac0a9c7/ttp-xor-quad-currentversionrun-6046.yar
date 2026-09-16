rule TTP_XOR_QUAD_CurrentVersionRun_6046 {
  strings:
    $key_6046 = { 33 29 [2] 17 27 [2] 3c 0b [2] 12 29 [2] 06 32 [2] 09 28 [2] 17 35 [2] 15 34 [2] 0e 32 [2] 12 35 [2] 0e 1a }

  condition:
    any of them
}