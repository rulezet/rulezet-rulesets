rule TTP_XOR_QUAD_CurrentVersionRun_7c60 {
  strings:
    $key_7c60 = { 2f 0f [2] 0b 01 [2] 20 2d [2] 0e 0f [2] 1a 14 [2] 15 0e [2] 0b 13 [2] 09 12 [2] 12 14 [2] 0e 13 [2] 12 3c }

  condition:
    any of them
}