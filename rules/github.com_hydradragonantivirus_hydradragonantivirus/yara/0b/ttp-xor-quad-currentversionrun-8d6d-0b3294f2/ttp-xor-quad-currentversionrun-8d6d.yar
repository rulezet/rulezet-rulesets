rule TTP_XOR_QUAD_CurrentVersionRun_8d6d {
  strings:
    $key_8d6d = { de 02 [2] fa 0c [2] d1 20 [2] ff 02 [2] eb 19 [2] e4 03 [2] fa 1e [2] f8 1f [2] e3 19 [2] ff 1e [2] e3 31 }

  condition:
    any of them
}