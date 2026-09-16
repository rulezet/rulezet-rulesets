rule TTP_XOR_QUAD_CurrentVersionRun_8df7 {
  strings:
    $key_8df7 = { de 98 [2] fa 96 [2] d1 ba [2] ff 98 [2] eb 83 [2] e4 99 [2] fa 84 [2] f8 85 [2] e3 83 [2] ff 84 [2] e3 ab }

  condition:
    any of them
}