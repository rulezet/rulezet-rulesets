rule TTP_XOR_QUAD_CurrentVersionRun_dc60 {
  strings:
    $key_dc60 = { 8f 0f [2] ab 01 [2] 80 2d [2] ae 0f [2] ba 14 [2] b5 0e [2] ab 13 [2] a9 12 [2] b2 14 [2] ae 13 [2] b2 3c }

  condition:
    any of them
}