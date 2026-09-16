rule TTP_XOR_QUAD_CurrentVersionRun_4c75 {
  strings:
    $key_4c75 = { 1f 1a [2] 3b 14 [2] 10 38 [2] 3e 1a [2] 2a 01 [2] 25 1b [2] 3b 06 [2] 39 07 [2] 22 01 [2] 3e 06 [2] 22 29 }

  condition:
    any of them
}