rule TTP_XOR_QUAD_CurrentVersionRun_dcfa {
  strings:
    $key_dcfa = { 8f 95 [2] ab 9b [2] 80 b7 [2] ae 95 [2] ba 8e [2] b5 94 [2] ab 89 [2] a9 88 [2] b2 8e [2] ae 89 [2] b2 a6 }

  condition:
    any of them
}