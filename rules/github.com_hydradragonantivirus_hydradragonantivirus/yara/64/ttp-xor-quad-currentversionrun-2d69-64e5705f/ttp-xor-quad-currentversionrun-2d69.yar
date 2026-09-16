rule TTP_XOR_QUAD_CurrentVersionRun_2d69 {
  strings:
    $key_2d69 = { 7e 06 [2] 5a 08 [2] 71 24 [2] 5f 06 [2] 4b 1d [2] 44 07 [2] 5a 1a [2] 58 1b [2] 43 1d [2] 5f 1a [2] 43 35 }

  condition:
    any of them
}