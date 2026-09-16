rule TTP_XOR_QUAD_CurrentVersionRun_6746 {
  strings:
    $key_6746 = { 34 29 [2] 10 27 [2] 3b 0b [2] 15 29 [2] 01 32 [2] 0e 28 [2] 10 35 [2] 12 34 [2] 09 32 [2] 15 35 [2] 09 1a }

  condition:
    any of them
}