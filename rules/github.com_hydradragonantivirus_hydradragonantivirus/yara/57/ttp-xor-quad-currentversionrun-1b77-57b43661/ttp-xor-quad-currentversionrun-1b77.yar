rule TTP_XOR_QUAD_CurrentVersionRun_1b77 {
  strings:
    $key_1b77 = { 48 18 [2] 6c 16 [2] 47 3a [2] 69 18 [2] 7d 03 [2] 72 19 [2] 6c 04 [2] 6e 05 [2] 75 03 [2] 69 04 [2] 75 2b }

  condition:
    any of them
}