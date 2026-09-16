rule TTP_XOR_QUAD_CurrentVersionRun_c061 {
  strings:
    $key_c061 = { 93 0e [2] b7 00 [2] 9c 2c [2] b2 0e [2] a6 15 [2] a9 0f [2] b7 12 [2] b5 13 [2] ae 15 [2] b2 12 [2] ae 3d }

  condition:
    any of them
}