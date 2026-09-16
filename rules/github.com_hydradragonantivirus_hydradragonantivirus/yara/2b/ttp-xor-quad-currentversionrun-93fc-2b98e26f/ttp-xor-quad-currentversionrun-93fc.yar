rule TTP_XOR_QUAD_CurrentVersionRun_93fc {
  strings:
    $key_93fc = { c0 93 [2] e4 9d [2] cf b1 [2] e1 93 [2] f5 88 [2] fa 92 [2] e4 8f [2] e6 8e [2] fd 88 [2] e1 8f [2] fd a0 }

  condition:
    any of them
}