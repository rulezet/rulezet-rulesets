rule TTP_XOR_QUAD_CurrentVersionRun_3e60 {
  strings:
    $key_3e60 = { 6d 0f [2] 49 01 [2] 62 2d [2] 4c 0f [2] 58 14 [2] 57 0e [2] 49 13 [2] 4b 12 [2] 50 14 [2] 4c 13 [2] 50 3c }

  condition:
    any of them
}