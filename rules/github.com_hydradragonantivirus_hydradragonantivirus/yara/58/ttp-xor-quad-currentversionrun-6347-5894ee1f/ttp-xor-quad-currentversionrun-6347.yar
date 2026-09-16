rule TTP_XOR_QUAD_CurrentVersionRun_6347 {
  strings:
    $key_6347 = { 30 28 [2] 14 26 [2] 3f 0a [2] 11 28 [2] 05 33 [2] 0a 29 [2] 14 34 [2] 16 35 [2] 0d 33 [2] 11 34 [2] 0d 1b }

  condition:
    any of them
}