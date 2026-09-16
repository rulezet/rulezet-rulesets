rule TTP_XOR_QUAD_CurrentVersionRun_8de6 {
  strings:
    $key_8de6 = { de 89 [2] fa 87 [2] d1 ab [2] ff 89 [2] eb 92 [2] e4 88 [2] fa 95 [2] f8 94 [2] e3 92 [2] ff 95 [2] e3 ba }

  condition:
    any of them
}