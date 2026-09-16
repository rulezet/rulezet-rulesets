rule TTP_XOR_QUAD_CurrentVersionRun_dc00 {
  strings:
    $key_dc00 = { 8f 6f [2] ab 61 [2] 80 4d [2] ae 6f [2] ba 74 [2] b5 6e [2] ab 73 [2] a9 72 [2] b2 74 [2] ae 73 [2] b2 5c }

  condition:
    any of them
}