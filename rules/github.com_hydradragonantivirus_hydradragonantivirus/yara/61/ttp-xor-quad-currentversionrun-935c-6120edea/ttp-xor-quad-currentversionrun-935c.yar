rule TTP_XOR_QUAD_CurrentVersionRun_935c {
  strings:
    $key_935c = { c0 33 [2] e4 3d [2] cf 11 [2] e1 33 [2] f5 28 [2] fa 32 [2] e4 2f [2] e6 2e [2] fd 28 [2] e1 2f [2] fd 00 }

  condition:
    any of them
}