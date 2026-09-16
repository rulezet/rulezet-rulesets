rule TTP_XOR_QUAD_CurrentVersionRun_7434 {
  strings:
    $key_7434 = { 27 5b [2] 03 55 [2] 28 79 [2] 06 5b [2] 12 40 [2] 1d 5a [2] 03 47 [2] 01 46 [2] 1a 40 [2] 06 47 [2] 1a 68 }

  condition:
    any of them
}