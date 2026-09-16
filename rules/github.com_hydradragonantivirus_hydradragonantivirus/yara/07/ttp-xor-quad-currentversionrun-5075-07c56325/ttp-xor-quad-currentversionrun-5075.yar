rule TTP_XOR_QUAD_CurrentVersionRun_5075 {
  strings:
    $key_5075 = { 03 1a [2] 27 14 [2] 0c 38 [2] 22 1a [2] 36 01 [2] 39 1b [2] 27 06 [2] 25 07 [2] 3e 01 [2] 22 06 [2] 3e 29 }

  condition:
    any of them
}