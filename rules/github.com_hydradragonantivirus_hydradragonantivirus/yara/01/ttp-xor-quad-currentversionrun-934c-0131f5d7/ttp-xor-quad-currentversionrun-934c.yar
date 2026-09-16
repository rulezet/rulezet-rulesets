rule TTP_XOR_QUAD_CurrentVersionRun_934c {
  strings:
    $key_934c = { c0 23 [2] e4 2d [2] cf 01 [2] e1 23 [2] f5 38 [2] fa 22 [2] e4 3f [2] e6 3e [2] fd 38 [2] e1 3f [2] fd 10 }

  condition:
    any of them
}