rule TTP_XOR_QUAD_CurrentVersionRun_c25e {
  strings:
    $key_c25e = { 91 31 [2] b5 3f [2] 9e 13 [2] b0 31 [2] a4 2a [2] ab 30 [2] b5 2d [2] b7 2c [2] ac 2a [2] b0 2d [2] ac 02 }

  condition:
    any of them
}