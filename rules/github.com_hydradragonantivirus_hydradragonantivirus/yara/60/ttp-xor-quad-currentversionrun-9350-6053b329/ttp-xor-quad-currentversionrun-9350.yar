rule TTP_XOR_QUAD_CurrentVersionRun_9350 {
  strings:
    $key_9350 = { c0 3f [2] e4 31 [2] cf 1d [2] e1 3f [2] f5 24 [2] fa 3e [2] e4 23 [2] e6 22 [2] fd 24 [2] e1 23 [2] fd 0c }

  condition:
    any of them
}