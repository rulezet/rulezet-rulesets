rule TTP_XOR_QUAD_CurrentVersionRun_7339 {
  strings:
    $key_7339 = { 20 56 [2] 04 58 [2] 2f 74 [2] 01 56 [2] 15 4d [2] 1a 57 [2] 04 4a [2] 06 4b [2] 1d 4d [2] 01 4a [2] 1d 65 }

  condition:
    any of them
}