rule TTP_XOR_QUAD_CurrentVersionRun_dc10 {
  strings:
    $key_dc10 = { 8f 7f [2] ab 71 [2] 80 5d [2] ae 7f [2] ba 64 [2] b5 7e [2] ab 63 [2] a9 62 [2] b2 64 [2] ae 63 [2] b2 4c }

  condition:
    any of them
}