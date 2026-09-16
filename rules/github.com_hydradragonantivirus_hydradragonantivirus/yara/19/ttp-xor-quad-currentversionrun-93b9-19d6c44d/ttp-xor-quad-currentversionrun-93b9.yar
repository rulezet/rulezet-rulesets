rule TTP_XOR_QUAD_CurrentVersionRun_93b9 {
  strings:
    $key_93b9 = { c0 d6 [2] e4 d8 [2] cf f4 [2] e1 d6 [2] f5 cd [2] fa d7 [2] e4 ca [2] e6 cb [2] fd cd [2] e1 ca [2] fd e5 }

  condition:
    any of them
}