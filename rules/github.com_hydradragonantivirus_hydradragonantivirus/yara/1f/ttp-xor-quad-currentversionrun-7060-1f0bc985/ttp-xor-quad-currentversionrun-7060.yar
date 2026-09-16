rule TTP_XOR_QUAD_CurrentVersionRun_7060 {
  strings:
    $key_7060 = { 23 0f [2] 07 01 [2] 2c 2d [2] 02 0f [2] 16 14 [2] 19 0e [2] 07 13 [2] 05 12 [2] 1e 14 [2] 02 13 [2] 1e 3c }

  condition:
    any of them
}