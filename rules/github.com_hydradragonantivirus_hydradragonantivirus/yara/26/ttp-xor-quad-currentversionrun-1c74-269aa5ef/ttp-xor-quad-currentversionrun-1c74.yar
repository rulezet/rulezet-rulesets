rule TTP_XOR_QUAD_CurrentVersionRun_1c74 {
  strings:
    $key_1c74 = { 4f 1b [2] 6b 15 [2] 40 39 [2] 6e 1b [2] 7a 00 [2] 75 1a [2] 6b 07 [2] 69 06 [2] 72 00 [2] 6e 07 [2] 72 28 }

  condition:
    any of them
}