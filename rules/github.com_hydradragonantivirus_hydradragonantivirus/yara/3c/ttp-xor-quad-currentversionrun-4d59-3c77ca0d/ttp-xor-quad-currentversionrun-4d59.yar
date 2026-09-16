rule TTP_XOR_QUAD_CurrentVersionRun_4d59 {
  strings:
    $key_4d59 = { 1e 36 [2] 3a 38 [2] 11 14 [2] 3f 36 [2] 2b 2d [2] 24 37 [2] 3a 2a [2] 38 2b [2] 23 2d [2] 3f 2a [2] 23 05 }

  condition:
    any of them
}