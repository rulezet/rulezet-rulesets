rule TTP_XOR_QUAD_CurrentVersionRun_c160 {
  strings:
    $key_c160 = { 92 0f [2] b6 01 [2] 9d 2d [2] b3 0f [2] a7 14 [2] a8 0e [2] b6 13 [2] b4 12 [2] af 14 [2] b3 13 [2] af 3c }

  condition:
    any of them
}