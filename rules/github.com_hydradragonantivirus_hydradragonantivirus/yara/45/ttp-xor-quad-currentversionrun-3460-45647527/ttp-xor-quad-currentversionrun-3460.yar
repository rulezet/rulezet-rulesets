rule TTP_XOR_QUAD_CurrentVersionRun_3460 {
  strings:
    $key_3460 = { 67 0f [2] 43 01 [2] 68 2d [2] 46 0f [2] 52 14 [2] 5d 0e [2] 43 13 [2] 41 12 [2] 5a 14 [2] 46 13 [2] 5a 3c }

  condition:
    any of them
}