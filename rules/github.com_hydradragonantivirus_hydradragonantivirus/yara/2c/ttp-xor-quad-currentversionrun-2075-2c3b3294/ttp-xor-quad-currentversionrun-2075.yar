rule TTP_XOR_QUAD_CurrentVersionRun_2075 {
  strings:
    $key_2075 = { 73 1a [2] 57 14 [2] 7c 38 [2] 52 1a [2] 46 01 [2] 49 1b [2] 57 06 [2] 55 07 [2] 4e 01 [2] 52 06 [2] 4e 29 }

  condition:
    any of them
}