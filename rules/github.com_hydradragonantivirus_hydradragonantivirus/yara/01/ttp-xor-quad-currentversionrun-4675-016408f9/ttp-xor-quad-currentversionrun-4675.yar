rule TTP_XOR_QUAD_CurrentVersionRun_4675 {
  strings:
    $key_4675 = { 15 1a [2] 31 14 [2] 1a 38 [2] 34 1a [2] 20 01 [2] 2f 1b [2] 31 06 [2] 33 07 [2] 28 01 [2] 34 06 [2] 28 29 }

  condition:
    any of them
}