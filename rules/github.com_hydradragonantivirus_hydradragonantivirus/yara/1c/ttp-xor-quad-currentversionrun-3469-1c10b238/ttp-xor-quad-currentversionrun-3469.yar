rule TTP_XOR_QUAD_CurrentVersionRun_3469 {
  strings:
    $key_3469 = { 67 06 [2] 43 08 [2] 68 24 [2] 46 06 [2] 52 1d [2] 5d 07 [2] 43 1a [2] 41 1b [2] 5a 1d [2] 46 1a [2] 5a 35 }

  condition:
    any of them
}