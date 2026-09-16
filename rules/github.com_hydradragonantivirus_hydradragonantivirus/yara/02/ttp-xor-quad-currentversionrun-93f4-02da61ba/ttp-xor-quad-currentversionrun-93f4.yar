rule TTP_XOR_QUAD_CurrentVersionRun_93f4 {
  strings:
    $key_93f4 = { c0 9b [2] e4 95 [2] cf b9 [2] e1 9b [2] f5 80 [2] fa 9a [2] e4 87 [2] e6 86 [2] fd 80 [2] e1 87 [2] fd a8 }

  condition:
    any of them
}