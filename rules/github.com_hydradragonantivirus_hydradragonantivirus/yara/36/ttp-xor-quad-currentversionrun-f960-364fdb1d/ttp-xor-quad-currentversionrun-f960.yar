rule TTP_XOR_QUAD_CurrentVersionRun_f960 {
  strings:
    $key_f960 = { aa 0f [2] 8e 01 [2] a5 2d [2] 8b 0f [2] 9f 14 [2] 90 0e [2] 8e 13 [2] 8c 12 [2] 97 14 [2] 8b 13 [2] 97 3c }

  condition:
    any of them
}