rule TTP_XOR_QUAD_CurrentVersionRun_1b75 {
  strings:
    $key_1b75 = { 48 1a [2] 6c 14 [2] 47 38 [2] 69 1a [2] 7d 01 [2] 72 1b [2] 6c 06 [2] 6e 07 [2] 75 01 [2] 69 06 [2] 75 29 }

  condition:
    any of them
}