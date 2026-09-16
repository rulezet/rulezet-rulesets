rule TTP_XOR_QUAD_CurrentVersionRun_2060 {
  strings:
    $key_2060 = { 73 0f [2] 57 01 [2] 7c 2d [2] 52 0f [2] 46 14 [2] 49 0e [2] 57 13 [2] 55 12 [2] 4e 14 [2] 52 13 [2] 4e 3c }

  condition:
    any of them
}