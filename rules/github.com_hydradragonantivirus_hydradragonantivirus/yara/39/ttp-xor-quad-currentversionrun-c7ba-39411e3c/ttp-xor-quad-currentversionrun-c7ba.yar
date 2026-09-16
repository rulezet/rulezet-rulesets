rule TTP_XOR_QUAD_CurrentVersionRun_c7ba {
  strings:
    $key_c7ba = { 94 d5 [2] b0 db [2] 9b f7 [2] b5 d5 [2] a1 ce [2] ae d4 [2] b0 c9 [2] b2 c8 [2] a9 ce [2] b5 c9 [2] a9 e6 }

  condition:
    any of them
}