rule TTP_XOR_QUAD_CurrentVersionRun_2246 {
  strings:
    $key_2246 = { 71 29 [2] 55 27 [2] 7e 0b [2] 50 29 [2] 44 32 [2] 4b 28 [2] 55 35 [2] 57 34 [2] 4c 32 [2] 50 35 [2] 4c 1a }

  condition:
    any of them
}