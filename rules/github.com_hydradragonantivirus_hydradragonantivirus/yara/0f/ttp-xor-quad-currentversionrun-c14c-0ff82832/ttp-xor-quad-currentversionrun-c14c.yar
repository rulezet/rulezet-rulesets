rule TTP_XOR_QUAD_CurrentVersionRun_c14c {
  strings:
    $key_c14c = { 92 23 [2] b6 2d [2] 9d 01 [2] b3 23 [2] a7 38 [2] a8 22 [2] b6 3f [2] b4 3e [2] af 38 [2] b3 3f [2] af 10 }

  condition:
    any of them
}