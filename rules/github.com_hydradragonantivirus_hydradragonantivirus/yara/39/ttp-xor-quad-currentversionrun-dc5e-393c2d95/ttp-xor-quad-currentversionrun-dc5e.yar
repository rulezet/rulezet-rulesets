rule TTP_XOR_QUAD_CurrentVersionRun_dc5e {
  strings:
    $key_dc5e = { 8f 31 [2] ab 3f [2] 80 13 [2] ae 31 [2] ba 2a [2] b5 30 [2] ab 2d [2] a9 2c [2] b2 2a [2] ae 2d [2] b2 02 }

  condition:
    any of them
}