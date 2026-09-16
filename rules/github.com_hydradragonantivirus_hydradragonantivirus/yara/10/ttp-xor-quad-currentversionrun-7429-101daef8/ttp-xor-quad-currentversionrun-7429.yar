rule TTP_XOR_QUAD_CurrentVersionRun_7429 {
  strings:
    $key_7429 = { 27 46 [2] 03 48 [2] 28 64 [2] 06 46 [2] 12 5d [2] 1d 47 [2] 03 5a [2] 01 5b [2] 1a 5d [2] 06 5a [2] 1a 75 }

  condition:
    any of them
}