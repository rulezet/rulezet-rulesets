rule TTP_XOR_QUAD_CurrentVersionRun_d6ba {
  strings:
    $key_d6ba = { 85 d5 [2] a1 db [2] 8a f7 [2] a4 d5 [2] b0 ce [2] bf d4 [2] a1 c9 [2] a3 c8 [2] b8 ce [2] a4 c9 [2] b8 e6 }

  condition:
    any of them
}