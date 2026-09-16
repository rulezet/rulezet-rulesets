rule TTP_XOR_QUAD_CurrentVersionRun_7359 {
  strings:
    $key_7359 = { 20 36 [2] 04 38 [2] 2f 14 [2] 01 36 [2] 15 2d [2] 1a 37 [2] 04 2a [2] 06 2b [2] 1d 2d [2] 01 2a [2] 1d 05 }

  condition:
    any of them
}