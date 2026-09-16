rule TTP_XOR_QUAD_CurrentVersionRun_1060 {
  strings:
    $key_1060 = { 43 0f [2] 67 01 [2] 4c 2d [2] 62 0f [2] 76 14 [2] 79 0e [2] 67 13 [2] 65 12 [2] 7e 14 [2] 62 13 [2] 7e 3c }

  condition:
    any of them
}