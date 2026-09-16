rule TTP_XOR_QUAD_CurrentVersionRun_c15e {
  strings:
    $key_c15e = { 92 31 [2] b6 3f [2] 9d 13 [2] b3 31 [2] a7 2a [2] a8 30 [2] b6 2d [2] b4 2c [2] af 2a [2] b3 2d [2] af 02 }

  condition:
    any of them
}