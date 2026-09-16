rule TTP_XOR_QUAD_CurrentVersionRun_93f2 {
  strings:
    $key_93f2 = { c0 9d [2] e4 93 [2] cf bf [2] e1 9d [2] f5 86 [2] fa 9c [2] e4 81 [2] e6 80 [2] fd 86 [2] e1 81 [2] fd ae }

  condition:
    any of them
}