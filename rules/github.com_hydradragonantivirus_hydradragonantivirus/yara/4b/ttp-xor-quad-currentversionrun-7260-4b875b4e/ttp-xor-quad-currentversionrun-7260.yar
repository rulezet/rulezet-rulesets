rule TTP_XOR_QUAD_CurrentVersionRun_7260 {
  strings:
    $key_7260 = { 21 0f [2] 05 01 [2] 2e 2d [2] 00 0f [2] 14 14 [2] 1b 0e [2] 05 13 [2] 07 12 [2] 1c 14 [2] 00 13 [2] 1c 3c }

  condition:
    any of them
}