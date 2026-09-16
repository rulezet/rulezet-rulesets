rule TTP_XOR_QUAD_CurrentVersionRun_3559 {
  strings:
    $key_3559 = { 66 36 [2] 42 38 [2] 69 14 [2] 47 36 [2] 53 2d [2] 5c 37 [2] 42 2a [2] 40 2b [2] 5b 2d [2] 47 2a [2] 5b 05 }

  condition:
    any of them
}