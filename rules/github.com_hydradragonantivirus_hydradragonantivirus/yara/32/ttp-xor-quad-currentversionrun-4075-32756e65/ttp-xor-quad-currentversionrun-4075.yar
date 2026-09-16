rule TTP_XOR_QUAD_CurrentVersionRun_4075 {
  strings:
    $key_4075 = { 13 1a [2] 37 14 [2] 1c 38 [2] 32 1a [2] 26 01 [2] 29 1b [2] 37 06 [2] 35 07 [2] 2e 01 [2] 32 06 [2] 2e 29 }

  condition:
    any of them
}