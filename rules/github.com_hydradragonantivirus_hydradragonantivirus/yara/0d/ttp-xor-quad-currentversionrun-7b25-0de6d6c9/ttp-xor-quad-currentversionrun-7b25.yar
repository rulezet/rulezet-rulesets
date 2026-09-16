rule TTP_XOR_QUAD_CurrentVersionRun_7b25 {
  strings:
    $key_7b25 = { 28 4a [2] 0c 44 [2] 27 68 [2] 09 4a [2] 1d 51 [2] 12 4b [2] 0c 56 [2] 0e 57 [2] 15 51 [2] 09 56 [2] 15 79 }

  condition:
    any of them
}