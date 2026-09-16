rule TTP_XOR_QUAD_CurrentVersionRun_5860 {
  strings:
    $key_5860 = { 0b 0f [2] 2f 01 [2] 04 2d [2] 2a 0f [2] 3e 14 [2] 31 0e [2] 2f 13 [2] 2d 12 [2] 36 14 [2] 2a 13 [2] 36 3c }

  condition:
    any of them
}