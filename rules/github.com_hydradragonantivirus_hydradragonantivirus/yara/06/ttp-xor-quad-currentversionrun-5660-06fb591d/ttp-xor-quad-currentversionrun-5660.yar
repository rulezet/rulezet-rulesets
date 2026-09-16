rule TTP_XOR_QUAD_CurrentVersionRun_5660 {
  strings:
    $key_5660 = { 05 0f [2] 21 01 [2] 0a 2d [2] 24 0f [2] 30 14 [2] 3f 0e [2] 21 13 [2] 23 12 [2] 38 14 [2] 24 13 [2] 38 3c }

  condition:
    any of them
}