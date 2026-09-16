rule TTP_XOR_QUAD_CurrentVersionRun_1347 {
  strings:
    $key_1347 = { 40 28 [2] 64 26 [2] 4f 0a [2] 61 28 [2] 75 33 [2] 7a 29 [2] 64 34 [2] 66 35 [2] 7d 33 [2] 61 34 [2] 7d 1b }

  condition:
    any of them
}