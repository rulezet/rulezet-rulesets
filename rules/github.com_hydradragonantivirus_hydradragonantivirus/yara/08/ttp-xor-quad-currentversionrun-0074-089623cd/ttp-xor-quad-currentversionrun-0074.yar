rule TTP_XOR_QUAD_CurrentVersionRun_0074 {
  strings:
    $key_0074 = { 53 1b [2] 77 15 [2] 5c 39 [2] 72 1b [2] 66 00 [2] 69 1a [2] 77 07 [2] 75 06 [2] 6e 00 [2] 72 07 [2] 6e 28 }

  condition:
    any of them
}