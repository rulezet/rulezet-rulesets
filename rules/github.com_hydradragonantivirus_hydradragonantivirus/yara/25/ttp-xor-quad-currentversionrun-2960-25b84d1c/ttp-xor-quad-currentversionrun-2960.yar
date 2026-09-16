rule TTP_XOR_QUAD_CurrentVersionRun_2960 {
  strings:
    $key_2960 = { 7a 0f [2] 5e 01 [2] 75 2d [2] 5b 0f [2] 4f 14 [2] 40 0e [2] 5e 13 [2] 5c 12 [2] 47 14 [2] 5b 13 [2] 47 3c }

  condition:
    any of them
}