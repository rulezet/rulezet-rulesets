rule TTP_XOR_QUAD_CurrentVersionRun_c75a {
  strings:
    $key_c75a = { 94 35 [2] b0 3b [2] 9b 17 [2] b5 35 [2] a1 2e [2] ae 34 [2] b0 29 [2] b2 28 [2] a9 2e [2] b5 29 [2] a9 06 }

  condition:
    any of them
}