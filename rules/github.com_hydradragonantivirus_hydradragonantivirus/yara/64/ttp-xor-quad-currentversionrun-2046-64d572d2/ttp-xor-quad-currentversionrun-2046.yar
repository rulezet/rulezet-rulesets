rule TTP_XOR_QUAD_CurrentVersionRun_2046 {
  strings:
    $key_2046 = { 73 29 [2] 57 27 [2] 7c 0b [2] 52 29 [2] 46 32 [2] 49 28 [2] 57 35 [2] 55 34 [2] 4e 32 [2] 52 35 [2] 4e 1a }

  condition:
    any of them
}