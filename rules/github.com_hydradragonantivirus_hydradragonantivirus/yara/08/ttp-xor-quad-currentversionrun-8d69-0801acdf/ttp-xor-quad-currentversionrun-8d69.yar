rule TTP_XOR_QUAD_CurrentVersionRun_8d69 {
  strings:
    $key_8d69 = { de 06 [2] fa 08 [2] d1 24 [2] ff 06 [2] eb 1d [2] e4 07 [2] fa 1a [2] f8 1b [2] e3 1d [2] ff 1a [2] e3 35 }

  condition:
    any of them
}