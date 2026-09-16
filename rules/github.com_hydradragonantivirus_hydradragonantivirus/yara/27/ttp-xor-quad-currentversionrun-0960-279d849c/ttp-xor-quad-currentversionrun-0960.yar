rule TTP_XOR_QUAD_CurrentVersionRun_0960 {
  strings:
    $key_0960 = { 5a 0f [2] 7e 01 [2] 55 2d [2] 7b 0f [2] 6f 14 [2] 60 0e [2] 7e 13 [2] 7c 12 [2] 67 14 [2] 7b 13 [2] 67 3c }

  condition:
    any of them
}