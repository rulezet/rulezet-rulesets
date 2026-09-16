rule TTP_XOR_QUAD_CurrentVersionRun_1b46 {
  strings:
    $key_1b46 = { 48 29 [2] 6c 27 [2] 47 0b [2] 69 29 [2] 7d 32 [2] 72 28 [2] 6c 35 [2] 6e 34 [2] 75 32 [2] 69 35 [2] 75 1a }

  condition:
    any of them
}