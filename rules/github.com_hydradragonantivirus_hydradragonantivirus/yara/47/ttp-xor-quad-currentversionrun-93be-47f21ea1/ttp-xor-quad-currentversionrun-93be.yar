rule TTP_XOR_QUAD_CurrentVersionRun_93be {
  strings:
    $key_93be = { c0 d1 [2] e4 df [2] cf f3 [2] e1 d1 [2] f5 ca [2] fa d0 [2] e4 cd [2] e6 cc [2] fd ca [2] e1 cd [2] fd e2 }

  condition:
    any of them
}