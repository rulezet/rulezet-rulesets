rule TTP_XOR_QUAD_CurrentVersionRun_4960 {
  strings:
    $key_4960 = { 1a 0f [2] 3e 01 [2] 15 2d [2] 3b 0f [2] 2f 14 [2] 20 0e [2] 3e 13 [2] 3c 12 [2] 27 14 [2] 3b 13 [2] 27 3c }

  condition:
    any of them
}