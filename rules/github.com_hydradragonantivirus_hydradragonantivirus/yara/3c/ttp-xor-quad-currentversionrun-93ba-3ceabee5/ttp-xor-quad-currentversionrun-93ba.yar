rule TTP_XOR_QUAD_CurrentVersionRun_93ba {
  strings:
    $key_93ba = { c0 d5 [2] e4 db [2] cf f7 [2] e1 d5 [2] f5 ce [2] fa d4 [2] e4 c9 [2] e6 c8 [2] fd ce [2] e1 c9 [2] fd e6 }

  condition:
    any of them
}