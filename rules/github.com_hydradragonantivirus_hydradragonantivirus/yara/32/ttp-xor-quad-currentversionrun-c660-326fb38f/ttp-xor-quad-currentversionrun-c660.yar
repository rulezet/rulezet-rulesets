rule TTP_XOR_QUAD_CurrentVersionRun_c660 {
  strings:
    $key_c660 = { 95 0f [2] b1 01 [2] 9a 2d [2] b4 0f [2] a0 14 [2] af 0e [2] b1 13 [2] b3 12 [2] a8 14 [2] b4 13 [2] a8 3c }

  condition:
    any of them
}