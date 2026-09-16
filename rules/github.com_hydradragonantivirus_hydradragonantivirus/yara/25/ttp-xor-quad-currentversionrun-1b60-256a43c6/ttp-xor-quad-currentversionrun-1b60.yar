rule TTP_XOR_QUAD_CurrentVersionRun_1b60 {
  strings:
    $key_1b60 = { 48 0f [2] 6c 01 [2] 47 2d [2] 69 0f [2] 7d 14 [2] 72 0e [2] 6c 13 [2] 6e 12 [2] 75 14 [2] 69 13 [2] 75 3c }

  condition:
    any of them
}