rule TTP_XOR_QUAD_CurrentVersionRun_7e60 {
  strings:
    $key_7e60 = { 2d 0f [2] 09 01 [2] 22 2d [2] 0c 0f [2] 18 14 [2] 17 0e [2] 09 13 [2] 0b 12 [2] 10 14 [2] 0c 13 [2] 10 3c }

  condition:
    any of them
}