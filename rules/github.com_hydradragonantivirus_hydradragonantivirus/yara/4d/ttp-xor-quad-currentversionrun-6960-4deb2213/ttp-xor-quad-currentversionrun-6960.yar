rule TTP_XOR_QUAD_CurrentVersionRun_6960 {
  strings:
    $key_6960 = { 3a 0f [2] 1e 01 [2] 35 2d [2] 1b 0f [2] 0f 14 [2] 00 0e [2] 1e 13 [2] 1c 12 [2] 07 14 [2] 1b 13 [2] 07 3c }

  condition:
    any of them
}