rule TTP_XOR_QUAD_CurrentVersionRun_8d42 {
  strings:
    $key_8d42 = { de 2d [2] fa 23 [2] d1 0f [2] ff 2d [2] eb 36 [2] e4 2c [2] fa 31 [2] f8 30 [2] e3 36 [2] ff 31 [2] e3 1e }

  condition:
    any of them
}