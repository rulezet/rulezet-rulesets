rule TTP_XOR_QUAD_CurrentVersionRun_8d63 {
  strings:
    $key_8d63 = { de 0c [2] fa 02 [2] d1 2e [2] ff 0c [2] eb 17 [2] e4 0d [2] fa 10 [2] f8 11 [2] e3 17 [2] ff 10 [2] e3 3f }

  condition:
    any of them
}