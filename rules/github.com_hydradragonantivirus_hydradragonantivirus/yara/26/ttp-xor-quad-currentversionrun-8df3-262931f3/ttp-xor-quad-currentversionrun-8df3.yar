rule TTP_XOR_QUAD_CurrentVersionRun_8df3 {
  strings:
    $key_8df3 = { de 9c [2] fa 92 [2] d1 be [2] ff 9c [2] eb 87 [2] e4 9d [2] fa 80 [2] f8 81 [2] e3 87 [2] ff 80 [2] e3 af }

  condition:
    any of them
}