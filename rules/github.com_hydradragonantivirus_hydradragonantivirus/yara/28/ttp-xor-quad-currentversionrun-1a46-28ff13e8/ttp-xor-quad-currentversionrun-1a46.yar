rule TTP_XOR_QUAD_CurrentVersionRun_1a46 {
  strings:
    $key_1a46 = { 49 29 [2] 6d 27 [2] 46 0b [2] 68 29 [2] 7c 32 [2] 73 28 [2] 6d 35 [2] 6f 34 [2] 74 32 [2] 68 35 [2] 74 1a }

  condition:
    any of them
}