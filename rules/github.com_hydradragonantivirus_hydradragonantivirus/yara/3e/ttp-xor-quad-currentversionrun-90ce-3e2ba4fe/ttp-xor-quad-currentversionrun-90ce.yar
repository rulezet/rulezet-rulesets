rule TTP_XOR_QUAD_CurrentVersionRun_90ce {
  strings:
    $key_90ce = { c3 a1 [2] e7 af [2] cc 83 [2] e2 a1 [2] f6 ba [2] f9 a0 [2] e7 bd [2] e5 bc [2] fe ba [2] e2 bd [2] fe 92 }

  condition:
    any of them
}