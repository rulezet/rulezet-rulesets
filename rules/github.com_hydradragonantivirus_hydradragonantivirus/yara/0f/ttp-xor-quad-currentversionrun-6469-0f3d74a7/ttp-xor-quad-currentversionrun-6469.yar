rule TTP_XOR_QUAD_CurrentVersionRun_6469 {
  strings:
    $key_6469 = { 37 06 [2] 13 08 [2] 38 24 [2] 16 06 [2] 02 1d [2] 0d 07 [2] 13 1a [2] 11 1b [2] 0a 1d [2] 16 1a [2] 0a 35 }

  condition:
    any of them
}