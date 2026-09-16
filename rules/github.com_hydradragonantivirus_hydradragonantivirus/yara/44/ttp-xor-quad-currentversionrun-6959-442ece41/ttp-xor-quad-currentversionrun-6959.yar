rule TTP_XOR_QUAD_CurrentVersionRun_6959 {
  strings:
    $key_6959 = { 3a 36 [2] 1e 38 [2] 35 14 [2] 1b 36 [2] 0f 2d [2] 00 37 [2] 1e 2a [2] 1c 2b [2] 07 2d [2] 1b 2a [2] 07 05 }

  condition:
    any of them
}