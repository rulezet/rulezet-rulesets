rule TTP_XOR_QUAD_CurrentVersionRun_d05e {
  strings:
    $key_d05e = { 83 31 [2] a7 3f [2] 8c 13 [2] a2 31 [2] b6 2a [2] b9 30 [2] a7 2d [2] a5 2c [2] be 2a [2] a2 2d [2] be 02 }

  condition:
    any of them
}