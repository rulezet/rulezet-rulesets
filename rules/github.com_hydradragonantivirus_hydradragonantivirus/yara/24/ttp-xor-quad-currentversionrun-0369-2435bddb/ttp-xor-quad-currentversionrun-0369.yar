rule TTP_XOR_QUAD_CurrentVersionRun_0369 {
  strings:
    $key_0369 = { 50 06 [2] 74 08 [2] 5f 24 [2] 71 06 [2] 65 1d [2] 6a 07 [2] 74 1a [2] 76 1b [2] 6d 1d [2] 71 1a [2] 6d 35 }

  condition:
    any of them
}