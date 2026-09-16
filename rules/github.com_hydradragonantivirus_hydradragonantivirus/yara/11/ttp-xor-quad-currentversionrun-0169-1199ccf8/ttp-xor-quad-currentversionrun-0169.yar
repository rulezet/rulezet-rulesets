rule TTP_XOR_QUAD_CurrentVersionRun_0169 {
  strings:
    $key_0169 = { 52 06 [2] 76 08 [2] 5d 24 [2] 73 06 [2] 67 1d [2] 68 07 [2] 76 1a [2] 74 1b [2] 6f 1d [2] 73 1a [2] 6f 35 }

  condition:
    any of them
}