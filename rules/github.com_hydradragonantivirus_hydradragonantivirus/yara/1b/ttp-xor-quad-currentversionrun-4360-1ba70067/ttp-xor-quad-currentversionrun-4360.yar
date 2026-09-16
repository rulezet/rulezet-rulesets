rule TTP_XOR_QUAD_CurrentVersionRun_4360 {
  strings:
    $key_4360 = { 10 0f [2] 34 01 [2] 1f 2d [2] 31 0f [2] 25 14 [2] 2a 0e [2] 34 13 [2] 36 12 [2] 2d 14 [2] 31 13 [2] 2d 3c }

  condition:
    any of them
}