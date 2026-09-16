rule TTP_XOR_QUAD_CurrentVersionRun_1559 {
  strings:
    $key_1559 = { 46 36 [2] 62 38 [2] 49 14 [2] 67 36 [2] 73 2d [2] 7c 37 [2] 62 2a [2] 60 2b [2] 7b 2d [2] 67 2a [2] 7b 05 }

  condition:
    any of them
}