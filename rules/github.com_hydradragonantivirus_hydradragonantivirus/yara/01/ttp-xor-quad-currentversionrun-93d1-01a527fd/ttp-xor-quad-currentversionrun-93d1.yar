rule TTP_XOR_QUAD_CurrentVersionRun_93d1 {
  strings:
    $key_93d1 = { c0 be [2] e4 b0 [2] cf 9c [2] e1 be [2] f5 a5 [2] fa bf [2] e4 a2 [2] e6 a3 [2] fd a5 [2] e1 a2 [2] fd 8d }

  condition:
    any of them
}