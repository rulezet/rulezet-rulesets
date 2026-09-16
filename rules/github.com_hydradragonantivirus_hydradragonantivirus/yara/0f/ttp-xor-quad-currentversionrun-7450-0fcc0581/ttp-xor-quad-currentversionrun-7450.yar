rule TTP_XOR_QUAD_CurrentVersionRun_7450 {
  strings:
    $key_7450 = { 27 3f [2] 03 31 [2] 28 1d [2] 06 3f [2] 12 24 [2] 1d 3e [2] 03 23 [2] 01 22 [2] 1a 24 [2] 06 23 [2] 1a 0c }

  condition:
    any of them
}