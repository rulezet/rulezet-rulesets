rule TTP_XOR_QUAD_CurrentVersionRun_7e06 {
  strings:
    $key_7e06 = { 2d 69 [2] 09 67 [2] 22 4b [2] 0c 69 [2] 18 72 [2] 17 68 [2] 09 75 [2] 0b 74 [2] 10 72 [2] 0c 75 [2] 10 5a }

  condition:
    any of them
}