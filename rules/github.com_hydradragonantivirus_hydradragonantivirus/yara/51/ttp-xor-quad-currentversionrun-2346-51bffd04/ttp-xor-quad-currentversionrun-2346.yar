rule TTP_XOR_QUAD_CurrentVersionRun_2346 {
  strings:
    $key_2346 = { 70 29 [2] 54 27 [2] 7f 0b [2] 51 29 [2] 45 32 [2] 4a 28 [2] 54 35 [2] 56 34 [2] 4d 32 [2] 51 35 [2] 4d 1a }

  condition:
    any of them
}