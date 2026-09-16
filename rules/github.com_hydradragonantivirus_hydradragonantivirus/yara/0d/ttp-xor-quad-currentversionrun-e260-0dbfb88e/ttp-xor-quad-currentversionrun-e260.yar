rule TTP_XOR_QUAD_CurrentVersionRun_e260 {
  strings:
    $key_e260 = { b1 0f [2] 95 01 [2] be 2d [2] 90 0f [2] 84 14 [2] 8b 0e [2] 95 13 [2] 97 12 [2] 8c 14 [2] 90 13 [2] 8c 3c }

  condition:
    any of them
}