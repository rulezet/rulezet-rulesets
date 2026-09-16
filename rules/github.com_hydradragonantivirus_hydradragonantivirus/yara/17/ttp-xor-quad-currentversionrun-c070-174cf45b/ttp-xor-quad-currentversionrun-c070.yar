rule TTP_XOR_QUAD_CurrentVersionRun_c070 {
  strings:
    $key_c070 = { 93 1f [2] b7 11 [2] 9c 3d [2] b2 1f [2] a6 04 [2] a9 1e [2] b7 03 [2] b5 02 [2] ae 04 [2] b2 03 [2] ae 2c }

  condition:
    any of them
}