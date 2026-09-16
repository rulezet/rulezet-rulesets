rule TTP_XOR_QUAD_CurrentVersionRun_dc63 {
  strings:
    $key_dc63 = { 8f 0c [2] ab 02 [2] 80 2e [2] ae 0c [2] ba 17 [2] b5 0d [2] ab 10 [2] a9 11 [2] b2 17 [2] ae 10 [2] b2 3f }

  condition:
    any of them
}