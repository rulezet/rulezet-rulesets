rule TTP_XOR_QUAD_CurrentVersionRun_4e06 {
  strings:
    $key_4e06 = { 1d 69 [2] 39 67 [2] 12 4b [2] 3c 69 [2] 28 72 [2] 27 68 [2] 39 75 [2] 3b 74 [2] 20 72 [2] 3c 75 [2] 20 5a }

  condition:
    any of them
}