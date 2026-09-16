rule TTP_XOR_QUAD_CurrentVersionRun_95ba {
  strings:
    $key_95ba = { c6 d5 [2] e2 db [2] c9 f7 [2] e7 d5 [2] f3 ce [2] fc d4 [2] e2 c9 [2] e0 c8 [2] fb ce [2] e7 c9 [2] fb e6 }

  condition:
    any of them
}