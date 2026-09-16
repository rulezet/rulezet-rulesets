rule TTP_XOR_QUAD_CurrentVersionRun_6060 {
  strings:
    $key_6060 = { 33 0f [2] 17 01 [2] 3c 2d [2] 12 0f [2] 06 14 [2] 09 0e [2] 17 13 [2] 15 12 [2] 0e 14 [2] 12 13 [2] 0e 3c }

  condition:
    any of them
}