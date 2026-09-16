rule TTP_XOR_QUAD_CurrentVersionRun_c140 {
  strings:
    $key_c140 = { 92 2f [2] b6 21 [2] 9d 0d [2] b3 2f [2] a7 34 [2] a8 2e [2] b6 33 [2] b4 32 [2] af 34 [2] b3 33 [2] af 1c }

  condition:
    any of them
}