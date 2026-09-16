rule TTP_XOR_QUAD_CurrentVersionRun_4059 {
  strings:
    $key_4059 = { 13 36 [2] 37 38 [2] 1c 14 [2] 32 36 [2] 26 2d [2] 29 37 [2] 37 2a [2] 35 2b [2] 2e 2d [2] 32 2a [2] 2e 05 }

  condition:
    any of them
}