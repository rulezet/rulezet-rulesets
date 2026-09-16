rule TTP_XOR_QUAD_CurrentVersionRun_1c75 {
  strings:
    $key_1c75 = { 4f 1a [2] 6b 14 [2] 40 38 [2] 6e 1a [2] 7a 01 [2] 75 1b [2] 6b 06 [2] 69 07 [2] 72 01 [2] 6e 06 [2] 72 29 }

  condition:
    any of them
}