rule TTP_XOR_QUAD_CurrentVersionRun_2660 {
  strings:
    $key_2660 = { 75 0f [2] 51 01 [2] 7a 2d [2] 54 0f [2] 40 14 [2] 4f 0e [2] 51 13 [2] 53 12 [2] 48 14 [2] 54 13 [2] 48 3c }

  condition:
    any of them
}