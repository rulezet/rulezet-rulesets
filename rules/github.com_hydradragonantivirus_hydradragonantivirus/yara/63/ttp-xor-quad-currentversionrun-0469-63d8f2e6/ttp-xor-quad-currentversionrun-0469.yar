rule TTP_XOR_QUAD_CurrentVersionRun_0469 {
  strings:
    $key_0469 = { 57 06 [2] 73 08 [2] 58 24 [2] 76 06 [2] 62 1d [2] 6d 07 [2] 73 1a [2] 71 1b [2] 6a 1d [2] 76 1a [2] 6a 35 }

  condition:
    any of them
}