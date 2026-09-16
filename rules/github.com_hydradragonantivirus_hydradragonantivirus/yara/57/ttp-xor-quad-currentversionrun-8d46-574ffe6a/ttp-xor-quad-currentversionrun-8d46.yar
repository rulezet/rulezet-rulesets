rule TTP_XOR_QUAD_CurrentVersionRun_8d46 {
  strings:
    $key_8d46 = { de 29 [2] fa 27 [2] d1 0b [2] ff 29 [2] eb 32 [2] e4 28 [2] fa 35 [2] f8 34 [2] e3 32 [2] ff 35 [2] e3 1a }

  condition:
    any of them
}