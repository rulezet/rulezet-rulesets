rule TTP_XOR_QUAD_CurrentVersionRun_935d {
  strings:
    $key_935d = { c0 32 [2] e4 3c [2] cf 10 [2] e1 32 [2] f5 29 [2] fa 33 [2] e4 2e [2] e6 2f [2] fd 29 [2] e1 2e [2] fd 01 }

  condition:
    any of them
}