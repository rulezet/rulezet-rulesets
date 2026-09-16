rule TTP_XOR_QUAD_CurrentVersionRun_8d13 {
  strings:
    $key_8d13 = { de 7c [2] fa 72 [2] d1 5e [2] ff 7c [2] eb 67 [2] e4 7d [2] fa 60 [2] f8 61 [2] e3 67 [2] ff 60 [2] e3 4f }

  condition:
    any of them
}