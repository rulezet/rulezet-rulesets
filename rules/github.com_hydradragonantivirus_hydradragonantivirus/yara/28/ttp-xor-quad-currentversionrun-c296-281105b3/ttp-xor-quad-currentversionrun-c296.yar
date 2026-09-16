rule TTP_XOR_QUAD_CurrentVersionRun_c296 {
  strings:
    $key_c296 = { 91 f9 [2] b5 f7 [2] 9e db [2] b0 f9 [2] a4 e2 [2] ab f8 [2] b5 e5 [2] b7 e4 [2] ac e2 [2] b0 e5 [2] ac ca }

  condition:
    any of them
}