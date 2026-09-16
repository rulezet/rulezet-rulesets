rule TTP_XOR_QUAD_CurrentVersionRun_7439 {
  strings:
    $key_7439 = { 27 56 [2] 03 58 [2] 28 74 [2] 06 56 [2] 12 4d [2] 1d 57 [2] 03 4a [2] 01 4b [2] 1a 4d [2] 06 4a [2] 1a 65 }

  condition:
    any of them
}