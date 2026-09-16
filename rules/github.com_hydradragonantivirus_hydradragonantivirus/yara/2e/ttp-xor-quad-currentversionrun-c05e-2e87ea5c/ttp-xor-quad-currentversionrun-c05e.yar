rule TTP_XOR_QUAD_CurrentVersionRun_c05e {
  strings:
    $key_c05e = { 93 31 [2] b7 3f [2] 9c 13 [2] b2 31 [2] a6 2a [2] a9 30 [2] b7 2d [2] b5 2c [2] ae 2a [2] b2 2d [2] ae 02 }

  condition:
    any of them
}