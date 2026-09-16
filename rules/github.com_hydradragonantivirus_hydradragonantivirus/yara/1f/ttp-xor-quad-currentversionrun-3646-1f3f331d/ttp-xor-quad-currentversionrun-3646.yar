rule TTP_XOR_QUAD_CurrentVersionRun_3646 {
  strings:
    $key_3646 = { 65 29 [2] 41 27 [2] 6a 0b [2] 44 29 [2] 50 32 [2] 5f 28 [2] 41 35 [2] 43 34 [2] 58 32 [2] 44 35 [2] 58 1a }

  condition:
    any of them
}