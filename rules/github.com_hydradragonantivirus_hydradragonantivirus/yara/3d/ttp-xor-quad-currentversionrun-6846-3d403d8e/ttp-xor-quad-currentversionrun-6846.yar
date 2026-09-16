rule TTP_XOR_QUAD_CurrentVersionRun_6846 {
  strings:
    $key_6846 = { 3b 29 [2] 1f 27 [2] 34 0b [2] 1a 29 [2] 0e 32 [2] 01 28 [2] 1f 35 [2] 1d 34 [2] 06 32 [2] 1a 35 [2] 06 1a }

  condition:
    any of them
}