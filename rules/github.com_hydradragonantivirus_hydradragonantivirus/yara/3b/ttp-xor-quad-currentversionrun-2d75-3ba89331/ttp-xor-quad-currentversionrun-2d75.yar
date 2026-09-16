rule TTP_XOR_QUAD_CurrentVersionRun_2d75 {
  strings:
    $key_2d75 = { 7e 1a [2] 5a 14 [2] 71 38 [2] 5f 1a [2] 4b 01 [2] 44 1b [2] 5a 06 [2] 58 07 [2] 43 01 [2] 5f 06 [2] 43 29 }

  condition:
    any of them
}