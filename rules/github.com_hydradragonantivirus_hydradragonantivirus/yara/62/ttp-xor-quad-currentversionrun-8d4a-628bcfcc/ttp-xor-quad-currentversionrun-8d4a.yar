rule TTP_XOR_QUAD_CurrentVersionRun_8d4a {
  strings:
    $key_8d4a = { de 25 [2] fa 2b [2] d1 07 [2] ff 25 [2] eb 3e [2] e4 24 [2] fa 39 [2] f8 38 [2] e3 3e [2] ff 39 [2] e3 16 }

  condition:
    any of them
}