rule TTP_XOR_QUAD_CurrentVersionRun_4846 {
  strings:
    $key_4846 = { 1b 29 [2] 3f 27 [2] 14 0b [2] 3a 29 [2] 2e 32 [2] 21 28 [2] 3f 35 [2] 3d 34 [2] 26 32 [2] 3a 35 [2] 26 1a }

  condition:
    any of them
}