rule TTP_XOR_QUAD_CurrentVersionRun_c04d {
  strings:
    $key_c04d = { 93 22 [2] b7 2c [2] 9c 00 [2] b2 22 [2] a6 39 [2] a9 23 [2] b7 3e [2] b5 3f [2] ae 39 [2] b2 3e [2] ae 11 }

  condition:
    any of them
}