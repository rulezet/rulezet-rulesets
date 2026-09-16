rule TTP_XOR_QUAD_CurrentVersionRun_1e74 {
  strings:
    $key_1e74 = { 4d 1b [2] 69 15 [2] 42 39 [2] 6c 1b [2] 78 00 [2] 77 1a [2] 69 07 [2] 6b 06 [2] 70 00 [2] 6c 07 [2] 70 28 }

  condition:
    any of them
}