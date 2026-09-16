rule TTP_XOR_QUAD_CurrentVersionRun_7360 {
  strings:
    $key_7360 = { 20 0f [2] 04 01 [2] 2f 2d [2] 01 0f [2] 15 14 [2] 1a 0e [2] 04 13 [2] 06 12 [2] 1d 14 [2] 01 13 [2] 1d 3c }

  condition:
    any of them
}