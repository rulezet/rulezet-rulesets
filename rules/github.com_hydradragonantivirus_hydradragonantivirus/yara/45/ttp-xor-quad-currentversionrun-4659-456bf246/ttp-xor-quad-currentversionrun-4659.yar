rule TTP_XOR_QUAD_CurrentVersionRun_4659 {
  strings:
    $key_4659 = { 15 36 [2] 31 38 [2] 1a 14 [2] 34 36 [2] 20 2d [2] 2f 37 [2] 31 2a [2] 33 2b [2] 28 2d [2] 34 2a [2] 28 05 }

  condition:
    any of them
}