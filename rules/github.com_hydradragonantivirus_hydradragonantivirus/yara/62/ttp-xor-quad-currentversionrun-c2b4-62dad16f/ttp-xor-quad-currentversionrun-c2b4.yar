rule TTP_XOR_QUAD_CurrentVersionRun_c2b4 {
  strings:
    $key_c2b4 = { 91 db [2] b5 d5 [2] 9e f9 [2] b0 db [2] a4 c0 [2] ab da [2] b5 c7 [2] b7 c6 [2] ac c0 [2] b0 c7 [2] ac e8 }

  condition:
    any of them
}