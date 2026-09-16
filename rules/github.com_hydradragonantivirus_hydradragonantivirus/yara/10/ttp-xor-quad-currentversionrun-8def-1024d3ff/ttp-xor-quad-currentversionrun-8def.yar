rule TTP_XOR_QUAD_CurrentVersionRun_8def {
  strings:
    $key_8def = { de 80 [2] fa 8e [2] d1 a2 [2] ff 80 [2] eb 9b [2] e4 81 [2] fa 9c [2] f8 9d [2] e3 9b [2] ff 9c [2] e3 b3 }

  condition:
    any of them
}