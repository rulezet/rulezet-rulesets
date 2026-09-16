rule TTP_XOR_QUAD_CurrentVersionRun_8d6e {
  strings:
    $key_8d6e = { de 01 [2] fa 0f [2] d1 23 [2] ff 01 [2] eb 1a [2] e4 00 [2] fa 1d [2] f8 1c [2] e3 1a [2] ff 1d [2] e3 32 }

  condition:
    any of them
}