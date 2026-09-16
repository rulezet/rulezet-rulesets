rule TTP_XOR_QUAD_CurrentVersionRun_c74c {
  strings:
    $key_c74c = { 94 23 [2] b0 2d [2] 9b 01 [2] b5 23 [2] a1 38 [2] ae 22 [2] b0 3f [2] b2 3e [2] a9 38 [2] b5 3f [2] a9 10 }

  condition:
    any of them
}