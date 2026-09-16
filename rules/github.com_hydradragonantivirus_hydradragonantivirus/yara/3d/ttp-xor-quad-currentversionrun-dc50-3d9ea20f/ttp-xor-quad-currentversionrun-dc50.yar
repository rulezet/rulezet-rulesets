rule TTP_XOR_QUAD_CurrentVersionRun_dc50 {
  strings:
    $key_dc50 = { 8f 3f [2] ab 31 [2] 80 1d [2] ae 3f [2] ba 24 [2] b5 3e [2] ab 23 [2] a9 22 [2] b2 24 [2] ae 23 [2] b2 0c }

  condition:
    any of them
}