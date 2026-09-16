rule TTP_XOR_QUAD_CurrentVersionRun_2360 {
  strings:
    $key_2360 = { 70 0f [2] 54 01 [2] 7f 2d [2] 51 0f [2] 45 14 [2] 4a 0e [2] 54 13 [2] 56 12 [2] 4d 14 [2] 51 13 [2] 4d 3c }

  condition:
    any of them
}