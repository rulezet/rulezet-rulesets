rule TTP_XOR_QUAD_CurrentVersionRun_c45e {
  strings:
    $key_c45e = { 97 31 [2] b3 3f [2] 98 13 [2] b6 31 [2] a2 2a [2] ad 30 [2] b3 2d [2] b1 2c [2] aa 2a [2] b6 2d [2] aa 02 }

  condition:
    any of them
}