rule TTP_XOR_QUAD_CurrentVersionRun_f260 {
  strings:
    $key_f260 = { a1 0f [2] 85 01 [2] ae 2d [2] 80 0f [2] 94 14 [2] 9b 0e [2] 85 13 [2] 87 12 [2] 9c 14 [2] 80 13 [2] 9c 3c }

  condition:
    any of them
}