rule TTP_XOR_QUAD_CurrentVersionRun_8d6f {
  strings:
    $key_8d6f = { de 00 [2] fa 0e [2] d1 22 [2] ff 00 [2] eb 1b [2] e4 01 [2] fa 1c [2] f8 1d [2] e3 1b [2] ff 1c [2] e3 33 }

  condition:
    any of them
}