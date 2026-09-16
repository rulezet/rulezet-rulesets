rule TTP_XOR_QUAD_CurrentVersionRun_3475 {
  strings:
    $key_3475 = { 67 1a [2] 43 14 [2] 68 38 [2] 46 1a [2] 52 01 [2] 5d 1b [2] 43 06 [2] 41 07 [2] 5a 01 [2] 46 06 [2] 5a 29 }

  condition:
    any of them
}