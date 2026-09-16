rule TTP_XOR_QUAD_CurrentVersionRun_8d49 {
  strings:
    $key_8d49 = { de 26 [2] fa 28 [2] d1 04 [2] ff 26 [2] eb 3d [2] e4 27 [2] fa 3a [2] f8 3b [2] e3 3d [2] ff 3a [2] e3 15 }

  condition:
    any of them
}