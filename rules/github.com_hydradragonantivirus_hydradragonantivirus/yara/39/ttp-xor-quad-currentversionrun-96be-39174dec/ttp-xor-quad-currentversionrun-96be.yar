rule TTP_XOR_QUAD_CurrentVersionRun_96be {
  strings:
    $key_96be = { c5 d1 [2] e1 df [2] ca f3 [2] e4 d1 [2] f0 ca [2] ff d0 [2] e1 cd [2] e3 cc [2] f8 ca [2] e4 cd [2] f8 e2 }

  condition:
    any of them
}