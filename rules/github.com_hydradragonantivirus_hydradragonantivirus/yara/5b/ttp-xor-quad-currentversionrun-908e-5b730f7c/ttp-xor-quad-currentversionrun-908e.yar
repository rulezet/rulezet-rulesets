rule TTP_XOR_QUAD_CurrentVersionRun_908e {
  strings:
    $key_908e = { c3 e1 [2] e7 ef [2] cc c3 [2] e2 e1 [2] f6 fa [2] f9 e0 [2] e7 fd [2] e5 fc [2] fe fa [2] e2 fd [2] fe d2 }

  condition:
    any of them
}