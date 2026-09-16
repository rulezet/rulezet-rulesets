rule TTP_XOR_QUAD_CurrentVersionRun_1377 {
  strings:
    $key_1377 = { 40 18 [2] 64 16 [2] 4f 3a [2] 61 18 [2] 75 03 [2] 7a 19 [2] 64 04 [2] 66 05 [2] 7d 03 [2] 61 04 [2] 7d 2b }

  condition:
    any of them
}