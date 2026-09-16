rule TTP_XOR_QUAD_CurrentVersionRun_7440 {
  strings:
    $key_7440 = { 27 2f [2] 03 21 [2] 28 0d [2] 06 2f [2] 12 34 [2] 1d 2e [2] 03 33 [2] 01 32 [2] 1a 34 [2] 06 33 [2] 1a 1c }

  condition:
    any of them
}