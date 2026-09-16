rule TTP_XOR_QUAD_CurrentVersionRun_c71d {
  strings:
    $key_c71d = { 94 72 [2] b0 7c [2] 9b 50 [2] b5 72 [2] a1 69 [2] ae 73 [2] b0 6e [2] b2 6f [2] a9 69 [2] b5 6e [2] a9 41 }

  condition:
    any of them
}