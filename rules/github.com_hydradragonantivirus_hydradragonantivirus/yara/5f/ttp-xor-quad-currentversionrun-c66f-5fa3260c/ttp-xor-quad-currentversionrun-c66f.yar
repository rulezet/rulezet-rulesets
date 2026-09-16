rule TTP_XOR_QUAD_CurrentVersionRun_c66f {
  strings:
    $key_c66f = { 95 00 [2] b1 0e [2] 9a 22 [2] b4 00 [2] a0 1b [2] af 01 [2] b1 1c [2] b3 1d [2] a8 1b [2] b4 1c [2] a8 33 }

  condition:
    any of them
}