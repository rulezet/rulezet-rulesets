rule TTP_XOR_QUAD_CurrentVersionRun_4c46 {
  strings:
    $key_4c46 = { 1f 29 [2] 3b 27 [2] 10 0b [2] 3e 29 [2] 2a 32 [2] 25 28 [2] 3b 35 [2] 39 34 [2] 22 32 [2] 3e 35 [2] 22 1a }

  condition:
    any of them
}