rule TTP_XOR_QUAD_CurrentVersionRun_dcfc {
  strings:
    $key_dcfc = { 8f 93 [2] ab 9d [2] 80 b1 [2] ae 93 [2] ba 88 [2] b5 92 [2] ab 8f [2] a9 8e [2] b2 88 [2] ae 8f [2] b2 a0 }

  condition:
    any of them
}