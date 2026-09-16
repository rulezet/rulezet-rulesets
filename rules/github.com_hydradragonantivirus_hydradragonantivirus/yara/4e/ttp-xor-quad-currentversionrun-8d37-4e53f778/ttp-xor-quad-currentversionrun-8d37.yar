rule TTP_XOR_QUAD_CurrentVersionRun_8d37 {
  strings:
    $key_8d37 = { de 58 [2] fa 56 [2] d1 7a [2] ff 58 [2] eb 43 [2] e4 59 [2] fa 44 [2] f8 45 [2] e3 43 [2] ff 44 [2] e3 6b }

  condition:
    any of them
}