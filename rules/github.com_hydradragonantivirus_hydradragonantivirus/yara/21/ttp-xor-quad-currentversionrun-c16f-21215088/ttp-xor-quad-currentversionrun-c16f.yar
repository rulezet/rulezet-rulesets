rule TTP_XOR_QUAD_CurrentVersionRun_c16f {
  strings:
    $key_c16f = { 92 00 [2] b6 0e [2] 9d 22 [2] b3 00 [2] a7 1b [2] a8 01 [2] b6 1c [2] b4 1d [2] af 1b [2] b3 1c [2] af 33 }

  condition:
    any of them
}