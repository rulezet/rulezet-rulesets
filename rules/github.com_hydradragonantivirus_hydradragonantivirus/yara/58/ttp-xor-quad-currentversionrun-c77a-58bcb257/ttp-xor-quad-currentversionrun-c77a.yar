rule TTP_XOR_QUAD_CurrentVersionRun_c77a {
  strings:
    $key_c77a = { 94 15 [2] b0 1b [2] 9b 37 [2] b5 15 [2] a1 0e [2] ae 14 [2] b0 09 [2] b2 08 [2] a9 0e [2] b5 09 [2] a9 26 }

  condition:
    any of them
}