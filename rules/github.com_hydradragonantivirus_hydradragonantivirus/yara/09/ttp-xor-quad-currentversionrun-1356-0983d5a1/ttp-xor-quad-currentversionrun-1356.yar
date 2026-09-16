rule TTP_XOR_QUAD_CurrentVersionRun_1356 {
  strings:
    $key_1356 = { 40 39 [2] 64 37 [2] 4f 1b [2] 61 39 [2] 75 22 [2] 7a 38 [2] 64 25 [2] 66 24 [2] 7d 22 [2] 61 25 [2] 7d 0a }

  condition:
    any of them
}