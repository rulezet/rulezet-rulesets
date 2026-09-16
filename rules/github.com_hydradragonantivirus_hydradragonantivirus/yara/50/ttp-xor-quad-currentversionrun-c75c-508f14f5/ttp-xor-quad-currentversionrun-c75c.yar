rule TTP_XOR_QUAD_CurrentVersionRun_c75c {
  strings:
    $key_c75c = { 94 33 [2] b0 3d [2] 9b 11 [2] b5 33 [2] a1 28 [2] ae 32 [2] b0 2f [2] b2 2e [2] a9 28 [2] b5 2f [2] a9 00 }

  condition:
    any of them
}