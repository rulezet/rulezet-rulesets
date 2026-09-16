rule TTP_XOR_QUAD_CurrentVersionRun_7e46 {
  strings:
    $key_7e46 = { 2d 29 [2] 09 27 [2] 22 0b [2] 0c 29 [2] 18 32 [2] 17 28 [2] 09 35 [2] 0b 34 [2] 10 32 [2] 0c 35 [2] 10 1a }

  condition:
    any of them
}