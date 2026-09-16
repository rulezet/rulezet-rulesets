rule TTP_XOR_QUAD_CurrentVersionRun_1b69 {
  strings:
    $key_1b69 = { 48 06 [2] 6c 08 [2] 47 24 [2] 69 06 [2] 7d 1d [2] 72 07 [2] 6c 1a [2] 6e 1b [2] 75 1d [2] 69 1a [2] 75 35 }

  condition:
    any of them
}