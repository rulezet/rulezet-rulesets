rule TTP_XOR_QUAD_CurrentVersionRun_4446 {
  strings:
    $key_4446 = { 17 29 [2] 33 27 [2] 18 0b [2] 36 29 [2] 22 32 [2] 2d 28 [2] 33 35 [2] 31 34 [2] 2a 32 [2] 36 35 [2] 2a 1a }

  condition:
    any of them
}