rule TTP_XOR_QUAD_CurrentVersionRun_3e46 {
  strings:
    $key_3e46 = { 6d 29 [2] 49 27 [2] 62 0b [2] 4c 29 [2] 58 32 [2] 57 28 [2] 49 35 [2] 4b 34 [2] 50 32 [2] 4c 35 [2] 50 1a }

  condition:
    any of them
}