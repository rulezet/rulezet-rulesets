rule TTP_XOR_QUAD_CurrentVersionRun_8d60 {
  strings:
    $key_8d60 = { de 0f [2] fa 01 [2] d1 2d [2] ff 0f [2] eb 14 [2] e4 0e [2] fa 13 [2] f8 12 [2] e3 14 [2] ff 13 [2] e3 3c }

  condition:
    any of them
}