rule TTP_XOR_QUAD_CurrentVersionRun_c14d {
  strings:
    $key_c14d = { 92 22 [2] b6 2c [2] 9d 00 [2] b3 22 [2] a7 39 [2] a8 23 [2] b6 3e [2] b4 3f [2] af 39 [2] b3 3e [2] af 11 }

  condition:
    any of them
}