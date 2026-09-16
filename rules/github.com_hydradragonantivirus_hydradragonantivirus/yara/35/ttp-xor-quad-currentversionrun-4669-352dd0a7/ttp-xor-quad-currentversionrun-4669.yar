rule TTP_XOR_QUAD_CurrentVersionRun_4669 {
  strings:
    $key_4669 = { 15 06 [2] 31 08 [2] 1a 24 [2] 34 06 [2] 20 1d [2] 2f 07 [2] 31 1a [2] 33 1b [2] 28 1d [2] 34 1a [2] 28 35 }

  condition:
    any of them
}