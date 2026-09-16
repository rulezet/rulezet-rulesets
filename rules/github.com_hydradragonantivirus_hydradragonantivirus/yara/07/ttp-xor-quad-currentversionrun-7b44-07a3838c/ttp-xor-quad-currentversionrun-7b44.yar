rule TTP_XOR_QUAD_CurrentVersionRun_7b44 {
  strings:
    $key_7b44 = { 28 2b [2] 0c 25 [2] 27 09 [2] 09 2b [2] 1d 30 [2] 12 2a [2] 0c 37 [2] 0e 36 [2] 15 30 [2] 09 37 [2] 15 18 }

  condition:
    any of them
}