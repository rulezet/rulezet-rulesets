rule TTP_XOR_QUAD_CurrentVersionRun_92ba {
  strings:
    $key_92ba = { c1 d5 [2] e5 db [2] ce f7 [2] e0 d5 [2] f4 ce [2] fb d4 [2] e5 c9 [2] e7 c8 [2] fc ce [2] e0 c9 [2] fc e6 }

  condition:
    any of them
}