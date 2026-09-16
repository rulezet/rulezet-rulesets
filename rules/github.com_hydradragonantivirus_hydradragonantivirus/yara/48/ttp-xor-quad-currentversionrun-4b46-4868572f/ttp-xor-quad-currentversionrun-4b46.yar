rule TTP_XOR_QUAD_CurrentVersionRun_4b46 {
  strings:
    $key_4b46 = { 18 29 [2] 3c 27 [2] 17 0b [2] 39 29 [2] 2d 32 [2] 22 28 [2] 3c 35 [2] 3e 34 [2] 25 32 [2] 39 35 [2] 25 1a }

  condition:
    any of them
}