rule TTP_XOR_QUAD_CurrentVersionRun_8d30 {
  strings:
    $key_8d30 = { de 5f [2] fa 51 [2] d1 7d [2] ff 5f [2] eb 44 [2] e4 5e [2] fa 43 [2] f8 42 [2] e3 44 [2] ff 43 [2] e3 6c }

  condition:
    any of them
}