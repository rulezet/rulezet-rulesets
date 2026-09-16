rule TTP_XOR_QUAD_CurrentVersionRun_c6ba {
  strings:
    $key_c6ba = { 95 d5 [2] b1 db [2] 9a f7 [2] b4 d5 [2] a0 ce [2] af d4 [2] b1 c9 [2] b3 c8 [2] a8 ce [2] b4 c9 [2] a8 e6 }

  condition:
    any of them
}