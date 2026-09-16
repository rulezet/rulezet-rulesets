rule TTP_XOR_QUAD_CurrentVersionRun_4760 {
  strings:
    $key_4760 = { 14 0f [2] 30 01 [2] 1b 2d [2] 35 0f [2] 21 14 [2] 2e 0e [2] 30 13 [2] 32 12 [2] 29 14 [2] 35 13 [2] 29 3c }

  condition:
    any of them
}