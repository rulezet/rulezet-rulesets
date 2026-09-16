rule TTP_XOR_QUAD_CurrentVersionRun_6260 {
  strings:
    $key_6260 = { 31 0f [2] 15 01 [2] 3e 2d [2] 10 0f [2] 04 14 [2] 0b 0e [2] 15 13 [2] 17 12 [2] 0c 14 [2] 10 13 [2] 0c 3c }

  condition:
    any of them
}