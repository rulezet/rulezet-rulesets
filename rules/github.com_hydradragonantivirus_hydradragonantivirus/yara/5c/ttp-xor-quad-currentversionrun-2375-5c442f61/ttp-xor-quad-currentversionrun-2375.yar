rule TTP_XOR_QUAD_CurrentVersionRun_2375 {
  strings:
    $key_2375 = { 70 1a [2] 54 14 [2] 7f 38 [2] 51 1a [2] 45 01 [2] 4a 1b [2] 54 06 [2] 56 07 [2] 4d 01 [2] 51 06 [2] 4d 29 }

  condition:
    any of them
}