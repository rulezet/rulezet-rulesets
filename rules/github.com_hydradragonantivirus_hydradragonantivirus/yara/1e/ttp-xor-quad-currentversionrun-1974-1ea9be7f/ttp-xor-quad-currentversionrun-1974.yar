rule TTP_XOR_QUAD_CurrentVersionRun_1974 {
  strings:
    $key_1974 = { 4a 1b [2] 6e 15 [2] 45 39 [2] 6b 1b [2] 7f 00 [2] 70 1a [2] 6e 07 [2] 6c 06 [2] 77 00 [2] 6b 07 [2] 77 28 }

  condition:
    any of them
}