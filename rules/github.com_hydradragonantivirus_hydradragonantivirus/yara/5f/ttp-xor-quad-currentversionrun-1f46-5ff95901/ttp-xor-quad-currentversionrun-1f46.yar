rule TTP_XOR_QUAD_CurrentVersionRun_1f46 {
  strings:
    $key_1f46 = { 4c 29 [2] 68 27 [2] 43 0b [2] 6d 29 [2] 79 32 [2] 76 28 [2] 68 35 [2] 6a 34 [2] 71 32 [2] 6d 35 [2] 71 1a }

  condition:
    any of them
}