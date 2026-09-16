rule TTP_XOR_QUAD_CurrentVersionRun_96ba {
  strings:
    $key_96ba = { c5 d5 [2] e1 db [2] ca f7 [2] e4 d5 [2] f0 ce [2] ff d4 [2] e1 c9 [2] e3 c8 [2] f8 ce [2] e4 c9 [2] f8 e6 }

  condition:
    any of them
}