rule TTP_XOR_QUAD_CurrentVersionRun_92ce {
  strings:
    $key_92ce = { c1 a1 [2] e5 af [2] ce 83 [2] e0 a1 [2] f4 ba [2] fb a0 [2] e5 bd [2] e7 bc [2] fc ba [2] e0 bd [2] fc 92 }

  condition:
    any of them
}