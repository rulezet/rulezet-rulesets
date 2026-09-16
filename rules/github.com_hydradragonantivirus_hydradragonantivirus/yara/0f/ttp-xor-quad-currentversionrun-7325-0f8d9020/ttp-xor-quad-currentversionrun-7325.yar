rule TTP_XOR_QUAD_CurrentVersionRun_7325 {
  strings:
    $key_7325 = { 20 4a [2] 04 44 [2] 2f 68 [2] 01 4a [2] 15 51 [2] 1a 4b [2] 04 56 [2] 06 57 [2] 1d 51 [2] 01 56 [2] 1d 79 }

  condition:
    any of them
}