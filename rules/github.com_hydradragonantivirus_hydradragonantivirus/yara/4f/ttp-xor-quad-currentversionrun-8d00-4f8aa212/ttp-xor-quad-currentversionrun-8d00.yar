rule TTP_XOR_QUAD_CurrentVersionRun_8d00 {
  strings:
    $key_8d00 = { de 6f [2] fa 61 [2] d1 4d [2] ff 6f [2] eb 74 [2] e4 6e [2] fa 73 [2] f8 72 [2] e3 74 [2] ff 73 [2] e3 5c }

  condition:
    any of them
}