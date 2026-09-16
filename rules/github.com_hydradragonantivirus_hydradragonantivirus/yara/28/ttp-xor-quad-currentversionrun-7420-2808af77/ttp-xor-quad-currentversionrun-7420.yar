rule TTP_XOR_QUAD_CurrentVersionRun_7420 {
  strings:
    $key_7420 = { 27 4f [2] 03 41 [2] 28 6d [2] 06 4f [2] 12 54 [2] 1d 4e [2] 03 53 [2] 01 52 [2] 1a 54 [2] 06 53 [2] 1a 7c }

  condition:
    any of them
}