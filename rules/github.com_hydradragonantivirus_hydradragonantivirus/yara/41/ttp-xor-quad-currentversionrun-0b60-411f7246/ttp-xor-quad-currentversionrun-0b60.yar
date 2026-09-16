rule TTP_XOR_QUAD_CurrentVersionRun_0b60 {
  strings:
    $key_0b60 = { 58 0f [2] 7c 01 [2] 57 2d [2] 79 0f [2] 6d 14 [2] 62 0e [2] 7c 13 [2] 7e 12 [2] 65 14 [2] 79 13 [2] 65 3c }

  condition:
    any of them
}