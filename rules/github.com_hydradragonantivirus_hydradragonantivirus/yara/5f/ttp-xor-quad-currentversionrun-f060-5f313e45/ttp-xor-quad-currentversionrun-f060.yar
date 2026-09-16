rule TTP_XOR_QUAD_CurrentVersionRun_f060 {
  strings:
    $key_f060 = { a3 0f [2] 87 01 [2] ac 2d [2] 82 0f [2] 96 14 [2] 99 0e [2] 87 13 [2] 85 12 [2] 9e 14 [2] 82 13 [2] 9e 3c }

  condition:
    any of them
}