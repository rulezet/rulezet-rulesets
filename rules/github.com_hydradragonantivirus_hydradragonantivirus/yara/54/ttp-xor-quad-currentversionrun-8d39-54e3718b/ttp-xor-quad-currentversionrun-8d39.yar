rule TTP_XOR_QUAD_CurrentVersionRun_8d39 {
  strings:
    $key_8d39 = { de 56 [2] fa 58 [2] d1 74 [2] ff 56 [2] eb 4d [2] e4 57 [2] fa 4a [2] f8 4b [2] e3 4d [2] ff 4a [2] e3 65 }

  condition:
    any of them
}