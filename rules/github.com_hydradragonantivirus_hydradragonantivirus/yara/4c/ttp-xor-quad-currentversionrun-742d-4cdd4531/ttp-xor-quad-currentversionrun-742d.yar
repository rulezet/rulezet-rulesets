rule TTP_XOR_QUAD_CurrentVersionRun_742d {
  strings:
    $key_742d = { 27 42 [2] 03 4c [2] 28 60 [2] 06 42 [2] 12 59 [2] 1d 43 [2] 03 5e [2] 01 5f [2] 1a 59 [2] 06 5e [2] 1a 71 }

  condition:
    any of them
}