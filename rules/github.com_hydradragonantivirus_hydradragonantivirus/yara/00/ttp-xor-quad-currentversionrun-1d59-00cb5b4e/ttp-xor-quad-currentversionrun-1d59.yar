rule TTP_XOR_QUAD_CurrentVersionRun_1d59 {
  strings:
    $key_1d59 = { 4e 36 [2] 6a 38 [2] 41 14 [2] 6f 36 [2] 7b 2d [2] 74 37 [2] 6a 2a [2] 68 2b [2] 73 2d [2] 6f 2a [2] 73 05 }

  condition:
    any of them
}