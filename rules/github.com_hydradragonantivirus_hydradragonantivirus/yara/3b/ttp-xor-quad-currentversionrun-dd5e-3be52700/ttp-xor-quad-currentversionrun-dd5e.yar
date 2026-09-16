rule TTP_XOR_QUAD_CurrentVersionRun_dd5e {
  strings:
    $key_dd5e = { 8e 31 [2] aa 3f [2] 81 13 [2] af 31 [2] bb 2a [2] b4 30 [2] aa 2d [2] a8 2c [2] b3 2a [2] af 2d [2] b3 02 }

  condition:
    any of them
}