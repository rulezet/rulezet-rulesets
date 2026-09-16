rule TTP_XOR_QUAD_CurrentVersionRun_93ce {
  strings:
    $key_93ce = { c0 a1 [2] e4 af [2] cf 83 [2] e1 a1 [2] f5 ba [2] fa a0 [2] e4 bd [2] e6 bc [2] fd ba [2] e1 bd [2] fd 92 }

  condition:
    any of them
}