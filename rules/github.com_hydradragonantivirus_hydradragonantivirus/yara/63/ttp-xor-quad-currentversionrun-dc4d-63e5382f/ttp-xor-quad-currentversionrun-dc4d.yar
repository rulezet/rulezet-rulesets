rule TTP_XOR_QUAD_CurrentVersionRun_dc4d {
  strings:
    $key_dc4d = { 8f 22 [2] ab 2c [2] 80 00 [2] ae 22 [2] ba 39 [2] b5 23 [2] ab 3e [2] a9 3f [2] b2 39 [2] ae 3e [2] b2 11 }

  condition:
    any of them
}