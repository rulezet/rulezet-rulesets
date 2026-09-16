rule TTP_XOR_QUAD_CurrentVersionRun_5645 {
  strings:
    $key_5645 = { 05 2a [2] 21 24 [2] 0a 08 [2] 24 2a [2] 30 31 [2] 3f 2b [2] 21 36 [2] 23 37 [2] 38 31 [2] 24 36 [2] 38 19 }

  condition:
    any of them
}