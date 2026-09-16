rule TTP_XOR_QUAD_CurrentVersionRun_dc62 {
  strings:
    $key_dc62 = { 8f 0d [2] ab 03 [2] 80 2f [2] ae 0d [2] ba 16 [2] b5 0c [2] ab 11 [2] a9 10 [2] b2 16 [2] ae 11 [2] b2 3e }

  condition:
    any of them
}