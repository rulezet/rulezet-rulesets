rule TTP_XOR_QUAD_CurrentVersionRun_8d2d {
  strings:
    $key_8d2d = { de 42 [2] fa 4c [2] d1 60 [2] ff 42 [2] eb 59 [2] e4 43 [2] fa 5e [2] f8 5f [2] e3 59 [2] ff 5e [2] e3 71 }

  condition:
    any of them
}