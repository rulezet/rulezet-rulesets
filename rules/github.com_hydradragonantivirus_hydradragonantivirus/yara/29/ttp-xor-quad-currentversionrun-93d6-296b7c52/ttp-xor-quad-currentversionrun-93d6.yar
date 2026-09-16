rule TTP_XOR_QUAD_CurrentVersionRun_93d6 {
  strings:
    $key_93d6 = { c0 b9 [2] e4 b7 [2] cf 9b [2] e1 b9 [2] f5 a2 [2] fa b8 [2] e4 a5 [2] e6 a4 [2] fd a2 [2] e1 a5 [2] fd 8a }

  condition:
    any of them
}