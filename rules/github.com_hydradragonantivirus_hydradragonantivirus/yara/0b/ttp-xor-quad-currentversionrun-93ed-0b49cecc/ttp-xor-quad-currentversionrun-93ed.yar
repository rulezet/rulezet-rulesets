rule TTP_XOR_QUAD_CurrentVersionRun_93ed {
  strings:
    $key_93ed = { c0 82 [2] e4 8c [2] cf a0 [2] e1 82 [2] f5 99 [2] fa 83 [2] e4 9e [2] e6 9f [2] fd 99 [2] e1 9e [2] fd b1 }

  condition:
    any of them
}