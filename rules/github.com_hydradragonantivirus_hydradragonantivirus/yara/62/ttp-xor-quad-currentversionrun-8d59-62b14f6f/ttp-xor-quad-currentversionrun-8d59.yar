rule TTP_XOR_QUAD_CurrentVersionRun_8d59 {
  strings:
    $key_8d59 = { de 36 [2] fa 38 [2] d1 14 [2] ff 36 [2] eb 2d [2] e4 37 [2] fa 2a [2] f8 2b [2] e3 2d [2] ff 2a [2] e3 05 }

  condition:
    any of them
}