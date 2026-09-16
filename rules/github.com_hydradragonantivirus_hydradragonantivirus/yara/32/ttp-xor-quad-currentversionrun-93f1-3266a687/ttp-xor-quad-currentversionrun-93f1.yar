rule TTP_XOR_QUAD_CurrentVersionRun_93f1 {
  strings:
    $key_93f1 = { c0 9e [2] e4 90 [2] cf bc [2] e1 9e [2] f5 85 [2] fa 9f [2] e4 82 [2] e6 83 [2] fd 85 [2] e1 82 [2] fd ad }

  condition:
    any of them
}