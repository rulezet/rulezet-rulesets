rule TTP_XOR_QUAD_CurrentVersionRun_1e69 {
  strings:
    $key_1e69 = { 4d 06 [2] 69 08 [2] 42 24 [2] 6c 06 [2] 78 1d [2] 77 07 [2] 69 1a [2] 6b 1b [2] 70 1d [2] 6c 1a [2] 70 35 }

  condition:
    any of them
}