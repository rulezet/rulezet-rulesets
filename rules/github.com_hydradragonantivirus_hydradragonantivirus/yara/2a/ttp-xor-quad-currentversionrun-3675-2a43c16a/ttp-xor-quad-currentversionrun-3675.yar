rule TTP_XOR_QUAD_CurrentVersionRun_3675 {
  strings:
    $key_3675 = { 65 1a [2] 41 14 [2] 6a 38 [2] 44 1a [2] 50 01 [2] 5f 1b [2] 41 06 [2] 43 07 [2] 58 01 [2] 44 06 [2] 58 29 }

  condition:
    any of them
}