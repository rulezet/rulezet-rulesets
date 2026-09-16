rule TTP_XOR_QUAD_CurrentVersionRun_4559 {
  strings:
    $key_4559 = { 16 36 [2] 32 38 [2] 19 14 [2] 37 36 [2] 23 2d [2] 2c 37 [2] 32 2a [2] 30 2b [2] 2b 2d [2] 37 2a [2] 2b 05 }

  condition:
    any of them
}