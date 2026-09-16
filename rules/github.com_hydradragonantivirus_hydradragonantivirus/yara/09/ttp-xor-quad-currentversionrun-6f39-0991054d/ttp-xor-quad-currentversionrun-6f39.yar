rule TTP_XOR_QUAD_CurrentVersionRun_6f39 {
  strings:
    $key_6f39 = { 3c 56 [2] 18 58 [2] 33 74 [2] 1d 56 [2] 09 4d [2] 06 57 [2] 18 4a [2] 1a 4b [2] 01 4d [2] 1d 4a [2] 01 65 }

  condition:
    any of them
}