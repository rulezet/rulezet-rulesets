rule TTP_XOR_QUAD_CurrentVersionRun_94a5 {
  strings:
    $key_94a5 = { c7 ca [2] e3 c4 [2] c8 e8 [2] e6 ca [2] f2 d1 [2] fd cb [2] e3 d6 [2] e1 d7 [2] fa d1 [2] e6 d6 [2] fa f9 }

  condition:
    any of them
}