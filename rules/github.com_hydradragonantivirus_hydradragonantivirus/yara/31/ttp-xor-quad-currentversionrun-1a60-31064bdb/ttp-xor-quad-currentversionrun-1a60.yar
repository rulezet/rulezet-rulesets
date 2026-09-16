rule TTP_XOR_QUAD_CurrentVersionRun_1a60 {
  strings:
    $key_1a60 = { 49 0f [2] 6d 01 [2] 46 2d [2] 68 0f [2] 7c 14 [2] 73 0e [2] 6d 13 [2] 6f 12 [2] 74 14 [2] 68 13 [2] 74 3c }

  condition:
    any of them
}