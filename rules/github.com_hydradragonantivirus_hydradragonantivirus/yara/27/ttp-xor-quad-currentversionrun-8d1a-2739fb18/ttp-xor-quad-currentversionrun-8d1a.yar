rule TTP_XOR_QUAD_CurrentVersionRun_8d1a {
  strings:
    $key_8d1a = { de 75 [2] fa 7b [2] d1 57 [2] ff 75 [2] eb 6e [2] e4 74 [2] fa 69 [2] f8 68 [2] e3 6e [2] ff 69 [2] e3 46 }

  condition:
    any of them
}