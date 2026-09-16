rule TTP_XOR_QUAD_CurrentVersionRun_4c60 {
  strings:
    $key_4c60 = { 1f 0f [2] 3b 01 [2] 10 2d [2] 3e 0f [2] 2a 14 [2] 25 0e [2] 3b 13 [2] 39 12 [2] 22 14 [2] 3e 13 [2] 22 3c }

  condition:
    any of them
}