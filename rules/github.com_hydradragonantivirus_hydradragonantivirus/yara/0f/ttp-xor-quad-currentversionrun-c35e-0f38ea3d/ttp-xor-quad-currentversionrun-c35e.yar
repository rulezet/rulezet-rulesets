rule TTP_XOR_QUAD_CurrentVersionRun_c35e {
  strings:
    $key_c35e = { 90 31 [2] b4 3f [2] 9f 13 [2] b1 31 [2] a5 2a [2] aa 30 [2] b4 2d [2] b6 2c [2] ad 2a [2] b1 2d [2] ad 02 }

  condition:
    any of them
}