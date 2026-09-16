rule TTP_XOR_QUAD_CurrentVersionRun_a7ba {
  strings:
    $key_a7ba = { f4 d5 [2] d0 db [2] fb f7 [2] d5 d5 [2] c1 ce [2] ce d4 [2] d0 c9 [2] d2 c8 [2] c9 ce [2] d5 c9 [2] c9 e6 }

  condition:
    any of them
}