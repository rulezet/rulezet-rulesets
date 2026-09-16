rule TTP_XOR_QUAD_CurrentVersionRun_3275 {
  strings:
    $key_3275 = { 61 1a [2] 45 14 [2] 6e 38 [2] 40 1a [2] 54 01 [2] 5b 1b [2] 45 06 [2] 47 07 [2] 5c 01 [2] 40 06 [2] 5c 29 }

  condition:
    any of them
}