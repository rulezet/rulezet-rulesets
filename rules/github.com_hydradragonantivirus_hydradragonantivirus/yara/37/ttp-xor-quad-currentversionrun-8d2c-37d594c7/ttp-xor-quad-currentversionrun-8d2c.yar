rule TTP_XOR_QUAD_CurrentVersionRun_8d2c {
  strings:
    $key_8d2c = { de 43 [2] fa 4d [2] d1 61 [2] ff 43 [2] eb 58 [2] e4 42 [2] fa 5f [2] f8 5e [2] e3 58 [2] ff 5f [2] e3 70 }

  condition:
    any of them
}