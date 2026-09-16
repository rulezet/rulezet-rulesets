rule TTP_XOR_QUAD_CurrentVersionRun_7b46 {
  strings:
    $key_7b46 = { 28 29 [2] 0c 27 [2] 27 0b [2] 09 29 [2] 1d 32 [2] 12 28 [2] 0c 35 [2] 0e 34 [2] 15 32 [2] 09 35 [2] 15 1a }

  condition:
    any of them
}