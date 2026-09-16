rule TTP_XOR_QUAD_CurrentVersionRun_c273 {
  strings:
    $key_c273 = { 91 1c [2] b5 12 [2] 9e 3e [2] b0 1c [2] a4 07 [2] ab 1d [2] b5 00 [2] b7 01 [2] ac 07 [2] b0 00 [2] ac 2f }

  condition:
    any of them
}