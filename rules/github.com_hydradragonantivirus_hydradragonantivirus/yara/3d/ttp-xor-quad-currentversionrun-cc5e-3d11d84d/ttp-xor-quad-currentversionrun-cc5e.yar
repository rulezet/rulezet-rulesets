rule TTP_XOR_QUAD_CurrentVersionRun_cc5e {
  strings:
    $key_cc5e = { 9f 31 [2] bb 3f [2] 90 13 [2] be 31 [2] aa 2a [2] a5 30 [2] bb 2d [2] b9 2c [2] a2 2a [2] be 2d [2] a2 02 }

  condition:
    any of them
}