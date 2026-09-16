rule TTP_XOR_QUAD_CurrentVersionRun_7309 {
  strings:
    $key_7309 = { 20 66 [2] 04 68 [2] 2f 44 [2] 01 66 [2] 15 7d [2] 1a 67 [2] 04 7a [2] 06 7b [2] 1d 7d [2] 01 7a [2] 1d 55 }

  condition:
    any of them
}