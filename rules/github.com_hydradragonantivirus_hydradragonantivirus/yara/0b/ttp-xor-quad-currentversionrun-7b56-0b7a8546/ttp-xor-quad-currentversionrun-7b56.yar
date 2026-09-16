rule TTP_XOR_QUAD_CurrentVersionRun_7b56 {
  strings:
    $key_7b56 = { 28 39 [2] 0c 37 [2] 27 1b [2] 09 39 [2] 1d 22 [2] 12 38 [2] 0c 25 [2] 0e 24 [2] 15 22 [2] 09 25 [2] 15 0a }

  condition:
    any of them
}