rule TTP_XOR_QUAD_CurrentVersionRun_2277 {
  strings:
    $key_2277 = { 71 18 [2] 55 16 [2] 7e 3a [2] 50 18 [2] 44 03 [2] 4b 19 [2] 55 04 [2] 57 05 [2] 4c 03 [2] 50 04 [2] 4c 2b }

  condition:
    any of them
}