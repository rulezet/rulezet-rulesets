rule TTP_XOR_QUAD_CurrentVersionRun_c55e {
  strings:
    $key_c55e = { 96 31 [2] b2 3f [2] 99 13 [2] b7 31 [2] a3 2a [2] ac 30 [2] b2 2d [2] b0 2c [2] ab 2a [2] b7 2d [2] ab 02 }

  condition:
    any of them
}