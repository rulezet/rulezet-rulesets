rule TTP_XOR_QUAD_CurrentVersionRun_7400 {
  strings:
    $key_7400 = { 27 6f [2] 03 61 [2] 28 4d [2] 06 6f [2] 12 74 [2] 1d 6e [2] 03 73 [2] 01 72 [2] 1a 74 [2] 06 73 [2] 1a 5c }

  condition:
    any of them
}