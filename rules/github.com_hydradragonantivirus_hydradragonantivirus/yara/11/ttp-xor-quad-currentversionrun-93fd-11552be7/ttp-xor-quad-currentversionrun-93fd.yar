rule TTP_XOR_QUAD_CurrentVersionRun_93fd {
  strings:
    $key_93fd = { c0 92 [2] e4 9c [2] cf b0 [2] e1 92 [2] f5 89 [2] fa 93 [2] e4 8e [2] e6 8f [2] fd 89 [2] e1 8e [2] fd a1 }

  condition:
    any of them
}