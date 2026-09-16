rule TTP_XOR_QUAD_CurrentVersionRun_7b77 {
  strings:
    $key_7b77 = { 28 18 [2] 0c 16 [2] 27 3a [2] 09 18 [2] 1d 03 [2] 12 19 [2] 0c 04 [2] 0e 05 [2] 15 03 [2] 09 04 [2] 15 2b }

  condition:
    any of them
}