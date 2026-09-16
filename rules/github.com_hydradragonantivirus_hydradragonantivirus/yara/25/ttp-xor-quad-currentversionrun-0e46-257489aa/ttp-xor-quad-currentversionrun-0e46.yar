rule TTP_XOR_QUAD_CurrentVersionRun_0e46 {
  strings:
    $key_0e46 = { 5d 29 [2] 79 27 [2] 52 0b [2] 7c 29 [2] 68 32 [2] 67 28 [2] 79 35 [2] 7b 34 [2] 60 32 [2] 7c 35 [2] 60 1a }

  condition:
    any of them
}