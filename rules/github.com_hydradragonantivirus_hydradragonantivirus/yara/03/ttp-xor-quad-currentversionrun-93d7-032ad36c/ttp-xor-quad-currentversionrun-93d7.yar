rule TTP_XOR_QUAD_CurrentVersionRun_93d7 {
  strings:
    $key_93d7 = { c0 b8 [2] e4 b6 [2] cf 9a [2] e1 b8 [2] f5 a3 [2] fa b9 [2] e4 a4 [2] e6 a5 [2] fd a3 [2] e1 a4 [2] fd 8b }

  condition:
    any of them
}