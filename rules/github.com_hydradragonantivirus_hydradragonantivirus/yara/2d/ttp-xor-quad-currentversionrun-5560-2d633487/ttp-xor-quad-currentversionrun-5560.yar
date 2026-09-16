rule TTP_XOR_QUAD_CurrentVersionRun_5560 {
  strings:
    $key_5560 = { 06 0f [2] 22 01 [2] 09 2d [2] 27 0f [2] 33 14 [2] 3c 0e [2] 22 13 [2] 20 12 [2] 3b 14 [2] 27 13 [2] 3b 3c }

  condition:
    any of them
}