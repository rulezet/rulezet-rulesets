rule TTP_XOR_QUAD_CurrentVersionRun_7660 {
  strings:
    $key_7660 = { 25 0f [2] 01 01 [2] 2a 2d [2] 04 0f [2] 10 14 [2] 1f 0e [2] 01 13 [2] 03 12 [2] 18 14 [2] 04 13 [2] 18 3c }

  condition:
    any of them
}