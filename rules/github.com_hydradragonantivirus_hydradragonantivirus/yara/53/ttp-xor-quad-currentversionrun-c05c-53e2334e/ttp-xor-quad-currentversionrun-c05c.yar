rule TTP_XOR_QUAD_CurrentVersionRun_c05c {
  strings:
    $key_c05c = { 93 33 [2] b7 3d [2] 9c 11 [2] b2 33 [2] a6 28 [2] a9 32 [2] b7 2f [2] b5 2e [2] ae 28 [2] b2 2f [2] ae 00 }

  condition:
    any of them
}