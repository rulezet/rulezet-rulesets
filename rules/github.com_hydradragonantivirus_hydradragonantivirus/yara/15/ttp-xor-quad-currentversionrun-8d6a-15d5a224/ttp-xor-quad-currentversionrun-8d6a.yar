rule TTP_XOR_QUAD_CurrentVersionRun_8d6a {
  strings:
    $key_8d6a = { de 05 [2] fa 0b [2] d1 27 [2] ff 05 [2] eb 1e [2] e4 04 [2] fa 19 [2] f8 18 [2] e3 1e [2] ff 19 [2] e3 36 }

  condition:
    any of them
}