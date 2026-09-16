rule TTP_XOR_QUAD_CurrentVersionRun_8d7c {
  strings:
    $key_8d7c = { de 13 [2] fa 1d [2] d1 31 [2] ff 13 [2] eb 08 [2] e4 12 [2] fa 0f [2] f8 0e [2] e3 08 [2] ff 0f [2] e3 20 }

  condition:
    any of them
}