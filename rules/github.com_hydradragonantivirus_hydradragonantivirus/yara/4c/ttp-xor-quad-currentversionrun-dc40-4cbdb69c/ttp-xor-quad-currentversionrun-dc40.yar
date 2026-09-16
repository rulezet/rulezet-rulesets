rule TTP_XOR_QUAD_CurrentVersionRun_dc40 {
  strings:
    $key_dc40 = { 8f 2f [2] ab 21 [2] 80 0d [2] ae 2f [2] ba 34 [2] b5 2e [2] ab 33 [2] a9 32 [2] b2 34 [2] ae 33 [2] b2 1c }

  condition:
    any of them
}