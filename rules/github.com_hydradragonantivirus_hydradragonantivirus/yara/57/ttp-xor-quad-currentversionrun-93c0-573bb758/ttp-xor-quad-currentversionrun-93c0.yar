rule TTP_XOR_QUAD_CurrentVersionRun_93c0 {
  strings:
    $key_93c0 = { c0 af [2] e4 a1 [2] cf 8d [2] e1 af [2] f5 b4 [2] fa ae [2] e4 b3 [2] e6 b2 [2] fd b4 [2] e1 b3 [2] fd 9c }

  condition:
    any of them
}