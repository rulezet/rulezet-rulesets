rule TTP_XOR_QUAD_CurrentVersionRun_8d09 {
  strings:
    $key_8d09 = { de 66 [2] fa 68 [2] d1 44 [2] ff 66 [2] eb 7d [2] e4 67 [2] fa 7a [2] f8 7b [2] e3 7d [2] ff 7a [2] e3 55 }

  condition:
    any of them
}