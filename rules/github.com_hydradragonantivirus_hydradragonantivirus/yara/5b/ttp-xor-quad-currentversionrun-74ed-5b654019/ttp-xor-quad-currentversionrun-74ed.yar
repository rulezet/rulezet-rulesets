rule TTP_XOR_QUAD_CurrentVersionRun_74ed {
  strings:
    $key_74ed = { 27 82 [2] 03 8c [2] 28 a0 [2] 06 82 [2] 12 99 [2] 1d 83 [2] 03 9e [2] 01 9f [2] 1a 99 [2] 06 9e [2] 1a b1 }

  condition:
    any of them
}