rule TTP_XOR_QUAD_CurrentVersionRun_93b8 {
  strings:
    $key_93b8 = { c0 d7 [2] e4 d9 [2] cf f5 [2] e1 d7 [2] f5 cc [2] fa d6 [2] e4 cb [2] e6 ca [2] fd cc [2] e1 cb [2] fd e4 }

  condition:
    any of them
}