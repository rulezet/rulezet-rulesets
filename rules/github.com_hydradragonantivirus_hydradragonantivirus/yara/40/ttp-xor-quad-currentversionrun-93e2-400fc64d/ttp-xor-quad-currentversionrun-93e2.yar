rule TTP_XOR_QUAD_CurrentVersionRun_93e2 {
  strings:
    $key_93e2 = { c0 8d [2] e4 83 [2] cf af [2] e1 8d [2] f5 96 [2] fa 8c [2] e4 91 [2] e6 90 [2] fd 96 [2] e1 91 [2] fd be }

  condition:
    any of them
}