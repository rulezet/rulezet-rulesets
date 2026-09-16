rule TTP_XOR_QUAD_CurrentVersionRun_3346 {
  strings:
    $key_3346 = { 60 29 [2] 44 27 [2] 6f 0b [2] 41 29 [2] 55 32 [2] 5a 28 [2] 44 35 [2] 46 34 [2] 5d 32 [2] 41 35 [2] 5d 1a }

  condition:
    any of them
}