rule TTP_XOR_QUAD_CurrentVersionRun_0e75 {
  strings:
    $key_0e75 = { 5d 1a [2] 79 14 [2] 52 38 [2] 7c 1a [2] 68 01 [2] 67 1b [2] 79 06 [2] 7b 07 [2] 60 01 [2] 7c 06 [2] 60 29 }

  condition:
    any of them
}