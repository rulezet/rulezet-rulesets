rule TTP_XOR_QUAD_CurrentVersionRun_c74d {
  strings:
    $key_c74d = { 94 22 [2] b0 2c [2] 9b 00 [2] b5 22 [2] a1 39 [2] ae 23 [2] b0 3e [2] b2 3f [2] a9 39 [2] b5 3e [2] a9 11 }

  condition:
    any of them
}