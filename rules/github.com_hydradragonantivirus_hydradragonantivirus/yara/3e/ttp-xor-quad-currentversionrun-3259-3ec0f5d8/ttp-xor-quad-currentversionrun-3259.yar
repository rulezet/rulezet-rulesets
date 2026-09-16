rule TTP_XOR_QUAD_CurrentVersionRun_3259 {
  strings:
    $key_3259 = { 61 36 [2] 45 38 [2] 6e 14 [2] 40 36 [2] 54 2d [2] 5b 37 [2] 45 2a [2] 47 2b [2] 5c 2d [2] 40 2a [2] 5c 05 }

  condition:
    any of them
}