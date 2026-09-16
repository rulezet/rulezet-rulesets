rule TTP_XOR_QUAD_CurrentVersionRun_dc4c {
  strings:
    $key_dc4c = { 8f 23 [2] ab 2d [2] 80 01 [2] ae 23 [2] ba 38 [2] b5 22 [2] ab 3f [2] a9 3e [2] b2 38 [2] ae 3f [2] b2 10 }

  condition:
    any of them
}