rule TTP_XOR_QUAD_CurrentVersionRun_c260 {
  strings:
    $key_c260 = { 91 0f [2] b5 01 [2] 9e 2d [2] b0 0f [2] a4 14 [2] ab 0e [2] b5 13 [2] b7 12 [2] ac 14 [2] b0 13 [2] ac 3c }

  condition:
    any of them
}