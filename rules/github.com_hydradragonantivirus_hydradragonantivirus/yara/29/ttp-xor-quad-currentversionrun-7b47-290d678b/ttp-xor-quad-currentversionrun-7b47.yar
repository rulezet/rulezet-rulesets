rule TTP_XOR_QUAD_CurrentVersionRun_7b47 {
  strings:
    $key_7b47 = { 28 28 [2] 0c 26 [2] 27 0a [2] 09 28 [2] 1d 33 [2] 12 29 [2] 0c 34 [2] 0e 35 [2] 15 33 [2] 09 34 [2] 15 1b }

  condition:
    any of them
}