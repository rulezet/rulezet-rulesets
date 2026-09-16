rule TTP_XOR_QUAD_CurrentVersionRun_96ce {
  strings:
    $key_96ce = { c5 a1 [2] e1 af [2] ca 83 [2] e4 a1 [2] f0 ba [2] ff a0 [2] e1 bd [2] e3 bc [2] f8 ba [2] e4 bd [2] f8 92 }

  condition:
    any of them
}