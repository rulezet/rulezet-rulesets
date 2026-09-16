rule TTP_XOR_QUAD_CurrentVersionRun_74ef {
  strings:
    $key_74ef = { 27 80 [2] 03 8e [2] 28 a2 [2] 06 80 [2] 12 9b [2] 1d 81 [2] 03 9c [2] 01 9d [2] 1a 9b [2] 06 9c [2] 1a b3 }

  condition:
    any of them
}