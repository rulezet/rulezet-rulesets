rule TTP_XOR_QUAD_CurrentVersionRun_2a46 {
  strings:
    $key_2a46 = { 79 29 [2] 5d 27 [2] 76 0b [2] 58 29 [2] 4c 32 [2] 43 28 [2] 5d 35 [2] 5f 34 [2] 44 32 [2] 58 35 [2] 44 1a }

  condition:
    any of them
}