rule TTP_XOR_QUAD_CurrentVersionRun_6f46 {
  strings:
    $key_6f46 = { 3c 29 [2] 18 27 [2] 33 0b [2] 1d 29 [2] 09 32 [2] 06 28 [2] 18 35 [2] 1a 34 [2] 01 32 [2] 1d 35 [2] 01 1a }

  condition:
    any of them
}