rule TTP_XOR_QUAD_CurrentVersionRun_8d2a {
  strings:
    $key_8d2a = { de 45 [2] fa 4b [2] d1 67 [2] ff 45 [2] eb 5e [2] e4 44 [2] fa 59 [2] f8 58 [2] e3 5e [2] ff 59 [2] e3 76 }

  condition:
    any of them
}