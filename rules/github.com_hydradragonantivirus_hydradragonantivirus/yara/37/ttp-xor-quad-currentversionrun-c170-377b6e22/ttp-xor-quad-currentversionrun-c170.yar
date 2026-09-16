rule TTP_XOR_QUAD_CurrentVersionRun_c170 {
  strings:
    $key_c170 = { 92 1f [2] b6 11 [2] 9d 3d [2] b3 1f [2] a7 04 [2] a8 1e [2] b6 03 [2] b4 02 [2] af 04 [2] b3 03 [2] af 2c }

  condition:
    any of them
}