rule TTP_XOR_QUAD_CurrentVersionRun_7b69 {
  strings:
    $key_7b69 = { 28 06 [2] 0c 08 [2] 27 24 [2] 09 06 [2] 1d 1d [2] 12 07 [2] 0c 1a [2] 0e 1b [2] 15 1d [2] 09 1a [2] 15 35 }

  condition:
    any of them
}