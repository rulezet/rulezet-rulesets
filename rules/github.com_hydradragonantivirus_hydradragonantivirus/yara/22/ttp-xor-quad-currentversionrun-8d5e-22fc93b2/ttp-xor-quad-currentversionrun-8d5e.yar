rule TTP_XOR_QUAD_CurrentVersionRun_8d5e {
  strings:
    $key_8d5e = { de 31 [2] fa 3f [2] d1 13 [2] ff 31 [2] eb 2a [2] e4 30 [2] fa 2d [2] f8 2c [2] e3 2a [2] ff 2d [2] e3 02 }

  condition:
    any of them
}