rule TTP_XOR_QUAD_CurrentVersionRun_8d5c {
  strings:
    $key_8d5c = { de 33 [2] fa 3d [2] d1 11 [2] ff 33 [2] eb 28 [2] e4 32 [2] fa 2f [2] f8 2e [2] e3 28 [2] ff 2f [2] e3 00 }

  condition:
    any of them
}