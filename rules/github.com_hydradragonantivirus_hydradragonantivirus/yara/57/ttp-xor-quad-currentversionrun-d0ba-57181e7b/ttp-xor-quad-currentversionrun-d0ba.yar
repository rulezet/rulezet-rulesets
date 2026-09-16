rule TTP_XOR_QUAD_CurrentVersionRun_d0ba {
  strings:
    $key_d0ba = { 83 d5 [2] a7 db [2] 8c f7 [2] a2 d5 [2] b6 ce [2] b9 d4 [2] a7 c9 [2] a5 c8 [2] be ce [2] a2 c9 [2] be e6 }

  condition:
    any of them
}