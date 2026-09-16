rule TTP_XOR_QUAD_CurrentVersionRun_8d5b {
  strings:
    $key_8d5b = { de 34 [2] fa 3a [2] d1 16 [2] ff 34 [2] eb 2f [2] e4 35 [2] fa 28 [2] f8 29 [2] e3 2f [2] ff 28 [2] e3 07 }

  condition:
    any of them
}