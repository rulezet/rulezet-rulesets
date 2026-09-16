rule TTP_XOR_QUAD_CurrentVersionRun_2257 {
  strings:
    $key_2257 = { 71 38 [2] 55 36 [2] 7e 1a [2] 50 38 [2] 44 23 [2] 4b 39 [2] 55 24 [2] 57 25 [2] 4c 23 [2] 50 24 [2] 4c 0b }

  condition:
    any of them
}