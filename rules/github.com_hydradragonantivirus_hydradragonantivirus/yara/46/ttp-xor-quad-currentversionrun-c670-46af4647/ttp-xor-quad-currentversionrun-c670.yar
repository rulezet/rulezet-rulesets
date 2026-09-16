rule TTP_XOR_QUAD_CurrentVersionRun_c670 {
  strings:
    $key_c670 = { 95 1f [2] b1 11 [2] 9a 3d [2] b4 1f [2] a0 04 [2] af 1e [2] b1 03 [2] b3 02 [2] a8 04 [2] b4 03 [2] a8 2c }

  condition:
    any of them
}