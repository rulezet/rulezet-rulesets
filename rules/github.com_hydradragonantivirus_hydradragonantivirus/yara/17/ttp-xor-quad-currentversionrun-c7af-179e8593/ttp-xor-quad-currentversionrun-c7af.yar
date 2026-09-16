rule TTP_XOR_QUAD_CurrentVersionRun_c7af {
  strings:
    $key_c7af = { 94 c0 [2] b0 ce [2] 9b e2 [2] b5 c0 [2] a1 db [2] ae c1 [2] b0 dc [2] b2 dd [2] a9 db [2] b5 dc [2] a9 f3 }

  condition:
    any of them
}