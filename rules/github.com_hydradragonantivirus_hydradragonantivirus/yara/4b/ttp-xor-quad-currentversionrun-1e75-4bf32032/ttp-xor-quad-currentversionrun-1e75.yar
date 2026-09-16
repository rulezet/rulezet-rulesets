rule TTP_XOR_QUAD_CurrentVersionRun_1e75 {
  strings:
    $key_1e75 = { 4d 1a [2] 69 14 [2] 42 38 [2] 6c 1a [2] 78 01 [2] 77 1b [2] 69 06 [2] 6b 07 [2] 70 01 [2] 6c 06 [2] 70 29 }

  condition:
    any of them
}