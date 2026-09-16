rule TTP_XOR_QUAD_CurrentVersionRun_0b46 {
  strings:
    $key_0b46 = { 58 29 [2] 7c 27 [2] 57 0b [2] 79 29 [2] 6d 32 [2] 62 28 [2] 7c 35 [2] 7e 34 [2] 65 32 [2] 79 35 [2] 65 1a }

  condition:
    any of them
}