rule TTP_XOR_QUAD_CurrentVersionRun_c71c {
  strings:
    $key_c71c = { 94 73 [2] b0 7d [2] 9b 51 [2] b5 73 [2] a1 68 [2] ae 72 [2] b0 6f [2] b2 6e [2] a9 68 [2] b5 6f [2] a9 40 }

  condition:
    any of them
}