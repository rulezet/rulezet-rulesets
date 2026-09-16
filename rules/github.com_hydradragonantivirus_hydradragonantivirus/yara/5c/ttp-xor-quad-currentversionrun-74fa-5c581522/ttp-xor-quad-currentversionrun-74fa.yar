rule TTP_XOR_QUAD_CurrentVersionRun_74fa {
  strings:
    $key_74fa = { 27 95 [2] 03 9b [2] 28 b7 [2] 06 95 [2] 12 8e [2] 1d 94 [2] 03 89 [2] 01 88 [2] 1a 8e [2] 06 89 [2] 1a a6 }

  condition:
    any of them
}