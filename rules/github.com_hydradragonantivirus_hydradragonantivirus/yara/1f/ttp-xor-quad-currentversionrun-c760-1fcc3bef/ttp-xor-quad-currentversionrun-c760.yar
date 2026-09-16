rule TTP_XOR_QUAD_CurrentVersionRun_c760 {
  strings:
    $key_c760 = { 94 0f [2] b0 01 [2] 9b 2d [2] b5 0f [2] a1 14 [2] ae 0e [2] b0 13 [2] b2 12 [2] a9 14 [2] b5 13 [2] a9 3c }

  condition:
    any of them
}