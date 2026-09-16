rule TTP_XOR_QUAD_CurrentVersionRun_c6b4 {
  strings:
    $key_c6b4 = { 95 db [2] b1 d5 [2] 9a f9 [2] b4 db [2] a0 c0 [2] af da [2] b1 c7 [2] b3 c6 [2] a8 c0 [2] b4 c7 [2] a8 e8 }

  condition:
    any of them
}