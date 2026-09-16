rule TTP_XOR_QUAD_CurrentVersionRun_935f {
  strings:
    $key_935f = { c0 30 [2] e4 3e [2] cf 12 [2] e1 30 [2] f5 2b [2] fa 31 [2] e4 2c [2] e6 2d [2] fd 2b [2] e1 2c [2] fd 03 }

  condition:
    any of them
}