rule TTP_XOR_QUAD_CurrentVersionRun_5160 {
  strings:
    $key_5160 = { 02 0f [2] 26 01 [2] 0d 2d [2] 23 0f [2] 37 14 [2] 38 0e [2] 26 13 [2] 24 12 [2] 3f 14 [2] 23 13 [2] 3f 3c }

  condition:
    any of them
}