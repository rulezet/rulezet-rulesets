rule TTP_XOR_QUAD_CurrentVersionRun_c76f {
  strings:
    $key_c76f = { 94 00 [2] b0 0e [2] 9b 22 [2] b5 00 [2] a1 1b [2] ae 01 [2] b0 1c [2] b2 1d [2] a9 1b [2] b5 1c [2] a9 33 }

  condition:
    any of them
}