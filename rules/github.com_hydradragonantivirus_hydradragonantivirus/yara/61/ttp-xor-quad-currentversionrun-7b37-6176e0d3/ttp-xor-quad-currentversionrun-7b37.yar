rule TTP_XOR_QUAD_CurrentVersionRun_7b37 {
  strings:
    $key_7b37 = { 28 58 [2] 0c 56 [2] 27 7a [2] 09 58 [2] 1d 43 [2] 12 59 [2] 0c 44 [2] 0e 45 [2] 15 43 [2] 09 44 [2] 15 6b }

  condition:
    any of them
}