rule TTP_XOR_QUAD_CurrentVersionRun_8d66 {
  strings:
    $key_8d66 = { de 09 [2] fa 07 [2] d1 2b [2] ff 09 [2] eb 12 [2] e4 08 [2] fa 15 [2] f8 14 [2] e3 12 [2] ff 15 [2] e3 3a }

  condition:
    any of them
}