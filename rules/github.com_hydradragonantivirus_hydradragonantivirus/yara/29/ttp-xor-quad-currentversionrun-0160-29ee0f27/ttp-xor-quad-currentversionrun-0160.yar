rule TTP_XOR_QUAD_CurrentVersionRun_0160 {
  strings:
    $key_0160 = { 52 0f [2] 76 01 [2] 5d 2d [2] 73 0f [2] 67 14 [2] 68 0e [2] 76 13 [2] 74 12 [2] 6f 14 [2] 73 13 [2] 6f 3c }

  condition:
    any of them
}