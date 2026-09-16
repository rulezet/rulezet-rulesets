rule TTP_XOR_QUAD_CurrentVersionRun_8d5d {
  strings:
    $key_8d5d = { de 32 [2] fa 3c [2] d1 10 [2] ff 32 [2] eb 29 [2] e4 33 [2] fa 2e [2] f8 2f [2] e3 29 [2] ff 2e [2] e3 01 }

  condition:
    any of them
}