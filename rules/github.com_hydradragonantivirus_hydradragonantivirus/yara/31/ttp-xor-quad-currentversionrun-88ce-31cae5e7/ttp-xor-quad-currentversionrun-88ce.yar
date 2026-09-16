rule TTP_XOR_QUAD_CurrentVersionRun_88ce {
  strings:
    $key_88ce = { db a1 [2] ff af [2] d4 83 [2] fa a1 [2] ee ba [2] e1 a0 [2] ff bd [2] fd bc [2] e6 ba [2] fa bd [2] e6 92 }

  condition:
    any of them
}