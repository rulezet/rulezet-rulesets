rule TTP_XOR_QUAD_CurrentVersionRun_7b57 {
  strings:
    $key_7b57 = { 28 38 [2] 0c 36 [2] 27 1a [2] 09 38 [2] 1d 23 [2] 12 39 [2] 0c 24 [2] 0e 25 [2] 15 23 [2] 09 24 [2] 15 0b }

  condition:
    any of them
}