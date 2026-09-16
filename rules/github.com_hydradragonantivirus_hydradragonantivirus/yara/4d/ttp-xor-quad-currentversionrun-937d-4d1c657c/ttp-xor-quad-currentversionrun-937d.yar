rule TTP_XOR_QUAD_CurrentVersionRun_937d {
  strings:
    $key_937d = { c0 12 [2] e4 1c [2] cf 30 [2] e1 12 [2] f5 09 [2] fa 13 [2] e4 0e [2] e6 0f [2] fd 09 [2] e1 0e [2] fd 21 }

  condition:
    any of them
}