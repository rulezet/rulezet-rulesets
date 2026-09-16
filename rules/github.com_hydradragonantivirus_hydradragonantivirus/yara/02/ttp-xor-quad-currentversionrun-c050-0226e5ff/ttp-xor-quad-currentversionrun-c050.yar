rule TTP_XOR_QUAD_CurrentVersionRun_c050 {
  strings:
    $key_c050 = { 93 3f [2] b7 31 [2] 9c 1d [2] b2 3f [2] a6 24 [2] a9 3e [2] b7 23 [2] b5 22 [2] ae 24 [2] b2 23 [2] ae 0c }

  condition:
    any of them
}