rule TTP_XOR_QUAD_CurrentVersionRun_935e {
  strings:
    $key_935e = { c0 31 [2] e4 3f [2] cf 13 [2] e1 31 [2] f5 2a [2] fa 30 [2] e4 2d [2] e6 2c [2] fd 2a [2] e1 2d [2] fd 02 }

  condition:
    any of them
}